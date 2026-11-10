package com.pareidolia.incidentmanagement.service;

import com.pareidolia.incidentmanagement.dto.IncidentTransferRequest;
import com.pareidolia.incidentmanagement.entity.AppUser;
import com.pareidolia.incidentmanagement.enums.AppUserRole;
import com.pareidolia.incidentmanagement.repository.IncidentRepository;
import com.pareidolia.incidentmanagement.security.IncidentAccessPolicy;
import com.pareidolia.incidentmanagement.security.IncidentReadSnapshot;
import com.pareidolia.incidentmanagement.security.IncidentSecurityGate;
import jakarta.persistence.EntityManager;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.web.server.ResponseStatusException;

@Service
@ConditionalOnProperty(name = {"app.incident-assignment.enabled", "app.incident-access.enabled",
        "app.employee-management.enabled", "app.hr-reassignment-referrals.enabled"}, havingValue = "true")
public class HrReassignmentReferralService {
    public enum Outcome { REJECTED, REASSIGNED, TRANSFERRED }

    public record Reassignment(Long handlerUserId, Long expectedVersion, Long expectedClassificationVersion) { }

    public record Decision(@NotNull Outcome outcome, @NotBlank @Size(max = 500) String reason,
                           Reassignment reassignment, @Valid IncidentTransferRequest transfer) { }

    public record Review(UUID referralId, long incidentId, long assignmentVersion,
                         long classificationVersion, Outcome outcome) { }

    /** Consume after commit and send only to the independently provisioned HR reviewer audience. */
    public record HrReferralQueued(UUID referralId) { }

    private static final Logger AUDIT = LoggerFactory.getLogger("incident.security.audit");
    private static final Pattern REFERENCE = Pattern.compile("INC-[0-9]{8}(?:[0-9]{4})?-[0-9]{6}-[A-F0-9]{8}");
    private static final int DAILY_INTAKE_LIMIT = 20;

    private final EntityManager em;
    private final IncidentRepository incidents;
    private final IncidentAssignmentService assignments;
    private final IncidentAccessPolicy access;
    private final IncidentSecurityGate gate;
    private final IncidentReadSnapshot snapshot;
    private final ApplicationEventPublisher events;
    private final Set<Long> itCoordinatorIds;
    private final Environment environment;

    public HrReassignmentReferralService(EntityManager em, IncidentRepository incidents,
            IncidentAssignmentService assignments, IncidentAccessPolicy access, IncidentSecurityGate gate,
            IncidentReadSnapshot snapshot, ApplicationEventPublisher events, Environment environment,
            @Value("${app.hr-reassignment-referrals.it-coordinator-ids:}") String coordinatorIds) {
        this.em = em;
        this.incidents = incidents;
        this.assignments = assignments;
        this.access = access;
        this.gate = gate;
        this.snapshot = snapshot;
        this.events = events;
        this.environment = environment;
        this.itCoordinatorIds = Arrays.stream(coordinatorIds.split(","))
                .map(String::trim).filter(id -> !id.isEmpty()).map(Long::valueOf).collect(Collectors.toUnmodifiableSet());
    }

    @Transactional
    public void submit(String reference) {
        gate.write();
        AppUser requester = assignments.referralCoordinator();
        if (!itCoordinatorIds.contains(requester.getId())
                || !Set.of(AppUserRole.ADMIN, AppUserRole.IT_HANDLER).contains(requester.getRole())) {
            AUDIT.warn("hr_referral_denied requester_id={}", requester.getId());
            throw new AccessDeniedException("Access denied.");
        }
        Timestamp cutoff = cutoff();
        Number attempts = (Number) em.createNativeQuery("""
                select count(*) from hr_reassignment_referral_intake
                where requester_id = :requester and received_at > :cutoff
                """).setParameter("requester", requester.getId()).setParameter("cutoff", cutoff).getSingleResult();
        if (attempts.longValue() >= DAILY_INTAKE_LIMIT) {
            AUDIT.warn("hr_referral_throttled requester_id={}", requester.getId());
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Referral intake limit reached.");
        }

        // Do not resolve the incident or consult decisions on this path.
        boolean queue = reference != null && reference.length() <= 40 && REFERENCE.matcher(reference).matches()
                && em.createNativeQuery("""
                        select id from hr_reassignment_referral_intake
                        where incident_reference = :reference and received_at > :cutoff
                        """).setParameter("reference", reference).setParameter("cutoff", cutoff)
                        .setMaxResults(1).getResultList().isEmpty();
        UUID id = UUID.randomUUID();
        if (em.createNativeQuery("""
                insert into hr_reassignment_referral_intake (id, requester_id, incident_reference)
                values (:id, :requester, :reference)
                """).setParameter("id", id.toString()).setParameter("requester", requester.getId())
                .setParameter("reference", queue ? reference : null).executeUpdate() != 1) {
            throw new IllegalStateException("Referral intake audit failed.");
        }
        if (queue) events.publishEvent(new HrReferralQueued(id));
    }

    public Review review(UUID referralId) {
        return snapshot.read(() -> findReview(referralId));
    }

    public List<UUID> pending() {
        return snapshot.read(() -> {
            AppUser reviewer = assignments.referralCoordinator();
            if (!access.hasHrAccountScope(reviewer) || !notificationReviewerIds().contains(reviewer.getId())) {
                throw new AccessDeniedException("Access denied.");
            }
            return pendingFor(reviewer, null).stream().limit(50).toList();
        });
    }

    public Set<Long> notificationReviewerIds() {
        return java.util.stream.Stream.of("primary-id", "backup-id")
                .map(key -> environment.getProperty("app.hr-reassignment-referrals.reviewers." + key, Long.class, 0L))
                .filter(id -> id > 0).collect(Collectors.toUnmodifiableSet());
    }

    /** Claims once before entering SMTP. An uncertain transport result must not be replayed automatically. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public String claimNotice(UUID referralId, long reviewerId, Set<String> allowedAddresses) {
        gate.write();
        if (!notificationReviewerIds().contains(reviewerId)) return null;
        AppUser reviewer = em.find(AppUser.class, reviewerId);
        if (reviewer == null || reviewer.getLastLoginAt() == null) return null;
        String email = AppUserService.normalizeEmail(reviewer.getEmail());
        if (email.isEmpty() || (allowedAddresses != null && !allowedAddresses.contains(email))
                || pendingFor(reviewer, referralId).isEmpty()) return null;
        var existing = em.createNativeQuery("""
                select referral_id from hr_referral_email_receipt where referral_id=:id and recipient_id=:reviewer
                """).setParameter("id", referralId.toString()).setParameter("reviewer", reviewerId).getResultList();
        if (!existing.isEmpty()) return null;
        if (em.createNativeQuery("""
                insert into hr_referral_email_receipt (referral_id, recipient_id, status)
                values (:id, :reviewer, 'CLAIMED')
                """).setParameter("id", referralId.toString()).setParameter("reviewer", reviewerId).executeUpdate() != 1) {
            throw new IllegalStateException("Referral email claim failed.");
        }
        return email;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordNoticeResult(UUID referralId, long reviewerId, boolean sent) {
        if (em.createNativeQuery("""
                update hr_referral_email_receipt set status=:result, finished_at=current_timestamp
                where referral_id=:id and recipient_id=:reviewer and status='CLAIMED'
                """).setParameter("id", referralId.toString()).setParameter("reviewer", reviewerId)
                .setParameter("result", sent ? "SENT" : "UNCERTAIN").executeUpdate() != 1) {
            throw new IllegalStateException("Referral email result could not be recorded.");
        }
    }

    private List<UUID> pendingFor(AppUser reviewer, UUID referralId) {
        if (!access.hasHrAccountScope(reviewer)) return List.of();
        var query = em.createNativeQuery("""
                select intake.id, intake.incident_reference, i.id
                from hr_reassignment_referral_intake intake
                join incidents i on i.incident_number=intake.incident_reference
                join incident_assignment_state a on a.incident_id=i.id and a.handler_user_id is not null
                join incident_security_grants v on v.incident_id=i.id and v.user_id=:reviewer and v.permission='VIEW' and v.active=1
                join incident_security_grants g on g.incident_id=i.id and g.user_id=:reviewer and g.permission='ASSIGN' and g.active=1
                left join hr_reassignment_referral_decision d on d.referral_id=intake.id
                where d.referral_id is null and intake.requester_id<>:reviewer and intake.received_at>:cutoff
                """ + (referralId == null ? "" : " and intake.id=:id") + " order by intake.received_at desc, intake.id")
                .setParameter("reviewer", reviewer.getId()).setParameter("cutoff", cutoff());
        if (referralId != null) query.setParameter("id", referralId.toString());
        @SuppressWarnings("unchecked")
        List<Object[]> rows = query.setMaxResults(200).getResultList();
        return rows.stream().flatMap(row -> incidents.findById(((Number) row[2]).longValue()).stream()
                .filter(incident -> row[1].equals(incident.getIncidentNumber()))
                .filter(incident -> reviewer.getRole() != AppUserRole.REPORTER
                        || AppUserService.normalizeEmail(reviewer.getEmail()).equals(AppUserService.normalizeEmail(incident.getReportedBy())))
                .filter(incident -> assignments.canReviewHrReferral(reviewer, incident))
                .map(incident -> UUID.fromString((String) row[0]))).toList();
    }

    @Transactional
    public void decide(UUID referralId, Decision decision) {
        gate.write();
        Review review = findReview(referralId);
        if (review.outcome() != null) throw new ResponseStatusException(HttpStatus.CONFLICT, "Referral already decided.");
        validateDecision(decision);
        AppUser reviewer = assignments.referralCoordinator();
        long version = switch (decision.outcome()) {
            case REJECTED -> review.assignmentVersion();
            case REASSIGNED -> {
                Reassignment change = decision.reassignment();
                yield assignments.assign(review.incidentId(), change.handlerUserId(), change.expectedVersion(),
                        change.expectedClassificationVersion(), decision.reason()).version();
            }
            case TRANSFERRED -> assignments.transfer(review.incidentId(), decision.transfer()).version();
        };
        if (em.createNativeQuery("""
                insert into hr_reassignment_referral_decision
                    (referral_id, reviewer_id, incident_id, outcome, assignment_version, reason)
                values (:referral, :reviewer, :incident, :outcome, :version, :reason)
                """).setParameter("referral", referralId.toString()).setParameter("reviewer", reviewer.getId())
                .setParameter("incident", review.incidentId()).setParameter("outcome", decision.outcome().name())
                .setParameter("version", version).setParameter("reason", decision.reason().trim()).executeUpdate() != 1) {
            throw new IllegalStateException("Referral decision audit failed.");
        }
    }

    private Review findReview(UUID referralId) {
        AppUser reviewer = assignments.referralCoordinator();
        if (!access.hasHrAccountScope(reviewer)) throw new AccessDeniedException("Access denied.");
        var rows = em.createNativeQuery("""
                select intake.incident_reference, decision.outcome
                from hr_reassignment_referral_intake intake
                left join hr_reassignment_referral_decision decision on decision.referral_id = intake.id
                where intake.id = :id and intake.requester_id <> :reviewer
                  and intake.received_at > :cutoff and intake.incident_reference is not null
                """).setParameter("id", referralId.toString()).setParameter("reviewer", reviewer.getId())
                .setParameter("cutoff", cutoff()).getResultList();
        if (rows.size() != 1) throw unavailable();
        Object[] row = (Object[]) rows.get(0);
        String reference = (String) row[0];
        var incident = incidents.findByIncidentNumber(reference)
                .filter(candidate -> reference.equals(candidate.getIncidentNumber())).orElseThrow(HrReassignmentReferralService::unavailable);
        var state = assignments.hrReferralCase(reviewer, incident);
        if (state == null) throw unavailable();
        return new Review(referralId, state.incidentId(), state.version(), state.classificationVersion(),
                row[1] == null ? null : Outcome.valueOf((String) row[1]));
    }

    private static void validateDecision(Decision decision) {
        if (decision == null || decision.outcome() == null || decision.reason() == null
                || decision.reason().isBlank() || decision.reason().length() > 500
                || (decision.outcome() == Outcome.REASSIGNED) != (decision.reassignment() != null)
                || (decision.outcome() == Outcome.TRANSFERRED) != (decision.transfer() != null)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Supply a decision and its matching action.");
        }
    }

    private static Timestamp cutoff() {
        return Timestamp.from(Instant.now().minus(1, ChronoUnit.DAYS));
    }

    private static ResponseStatusException unavailable() {
        return new ResponseStatusException(HttpStatus.NOT_FOUND, "Referral unavailable.");
    }
}
