package com.pareidolia.incidentmanagement.service.impl;

import com.pareidolia.incidentmanagement.dto.*;
import com.pareidolia.incidentmanagement.entity.AppUser;
import com.pareidolia.incidentmanagement.entity.Incident;
import com.pareidolia.incidentmanagement.entity.IncidentHistory;
import com.pareidolia.incidentmanagement.enums.AppUserRole;
import com.pareidolia.incidentmanagement.enums.HistoryActionType;
import com.pareidolia.incidentmanagement.enums.IncidentStatus;
import com.pareidolia.incidentmanagement.exception.IncidentNotFoundException;
import com.pareidolia.incidentmanagement.exception.InvalidIncidentStateException;
import com.pareidolia.incidentmanagement.exception.InvalidRequestException;
import com.pareidolia.incidentmanagement.mapper.IncidentMapper;
import com.pareidolia.incidentmanagement.repository.IncidentHistoryRepository;
import com.pareidolia.incidentmanagement.repository.IncidentRepository;
import com.pareidolia.incidentmanagement.service.IncidentService;
import com.pareidolia.incidentmanagement.security.IncidentConfidentiality;
import com.pareidolia.incidentmanagement.security.IncidentAccessPolicy.ReadOperation;
import com.pareidolia.incidentmanagement.service.AppUserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import com.pareidolia.incidentmanagement.notification.IncidentCreated;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

@Service
public class IncidentServiceImpl implements IncidentService {
    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private com.pareidolia.incidentmanagement.security.IncidentSecurityGate securityGate;
    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private com.pareidolia.incidentmanagement.security.IncidentReadSnapshot readSnapshot;
    private void securityWrite() {
        if (incidentAccessEnabled) {
            if (securityGate == null) throw new IllegalStateException("Security gate unavailable.");
            securityGate.write();
        } else {
            secureRead(() -> null); // Hold the rollback read gate through the mutation transaction.
        }
    }

    private <T> T secureRead(java.util.function.Supplier<T> work) {
        if (readSnapshot == null) throw new IllegalStateException("Security snapshot unavailable.");
        return incidentAccessEnabled ? readSnapshot.read(work) : readSnapshot.readForRollback(work);
    }

    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private com.pareidolia.incidentmanagement.service.IncidentAssignmentService employeeAssignment;
    @Value("${app.incident-assignment.enabled:false}") private boolean employeeAssignmentEnabled;

    private static final String SYSTEM_ACTOR = "SYSTEM";
    private static final DateTimeFormatter INCIDENT_YEAR_FORMAT = DateTimeFormatter.ofPattern("yyyy");
    private static final DateTimeFormatter INCIDENT_TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");

    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private com.pareidolia.incidentmanagement.security.IncidentAccessPolicy accessPolicy;
    @Value("${app.incident-access.enabled:false}") private boolean incidentAccessEnabled;
    private final IncidentRepository incidentRepository;
    private final IncidentHistoryRepository incidentHistoryRepository;
    private final IncidentMapper incidentMapper;
    private final AppUserService appUserService;
    private final String defaultItOwner;
    private final ApplicationEventPublisher events;
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private com.pareidolia.incidentmanagement.notification.IncidentOversightNotifications oversightNotifications;

    public IncidentServiceImpl(
            IncidentRepository incidentRepository,
            IncidentHistoryRepository incidentHistoryRepository,
            IncidentMapper incidentMapper,
            AppUserService appUserService,
            @Value("${app.default-it-owner}") String defaultItOwner,
            ApplicationEventPublisher events
    ) {
        this.incidentRepository = incidentRepository;
        this.incidentHistoryRepository = incidentHistoryRepository;
        this.incidentMapper = incidentMapper;
        this.appUserService = appUserService;
        this.defaultItOwner = defaultItOwner.trim();
        this.events = events;
    }

    @Override
    @Transactional
    public IncidentResponseDto createIncident(CreateIncidentRequestDto request) {
        if (incidentAccessEnabled) securityWrite();
        AppUser actor = getAuthenticatedUser();
        requireRole(actor, AppUserRole.REPORTER, AppUserRole.ADMIN);

        if(employeeAssignmentEnabled && (!incidentAccessEnabled || employeeAssignment==null))throw new IllegalStateException("Secure assignment dependencies unavailable.");
        if(!employeeAssignmentEnabled && request.getProposedHandlerUserId()!=null)throw new IllegalArgumentException("Employee assignment is disabled.");

        Long departmentId = request.getResponsibleDepartmentId();
        if (departmentId == null && departmentScopedIntakeAvailable()) {
            throw new InvalidRequestException("Select an active responsible department.");
        }
        String responsibleDepartmentName = null;
        if (departmentId != null) {
            if (!departmentScopedIntakeAvailable()) {
                throw new InvalidRequestException("Department-scoped intake is unavailable until secure assignment is enabled.");
            }
            if (departmentId <= 0) {
                throw new InvalidRequestException("Select an active responsible department.");
            }
            responsibleDepartmentName = incidentRepository.lockActiveResponsibleDepartmentName(departmentId)
                    .filter(com.pareidolia.incidentmanagement.service.ResponsibleDepartments::includes)
                    .orElseThrow(() -> new InvalidRequestException("Select an active responsible department."));
        }

        Incident incident = incidentMapper.toEntity(request);
        incident.setReportedBy(actor.getEmail());
        incident.setIncidentNumber(generateIncidentNumber());
        boolean pending = incidentAccessEnabled || departmentId != null
                || IncidentConfidentiality.requiresRestriction(incident, responsibleDepartmentName);
        incident.setAssignedOwner(pending ? null : defaultItOwner);
        incident.setStatus(pending ? IncidentStatus.OPEN : IncidentStatus.ASSIGNED);

        Incident savedIncident = incidentRepository.save(incident);
        if(employeeAssignmentEnabled)employeeAssignment.initialize(savedIncident,request.getProposedHandlerUserId());
        recordHistory(
                savedIncident,
                HistoryActionType.INCIDENT_CREATED,
                null,
                savedIncident.getIncidentNumber(),
                actor.getEmail(),
                null
        );
        if (!pending) recordHistory(
                savedIncident,
                HistoryActionType.OWNER_ASSIGNED,
                null,
                savedIncident.getAssignedOwner(),
                SYSTEM_ACTOR,
                "Automatically assigned to the configured default IT owner."
        );
        if (oversightNotifications != null) oversightNotifications.record(savedIncident.getId());
        events.publishEvent(new IncidentCreated(savedIncident.getIncidentNumber(), savedIncident.getTitle(),
                actor.getDisplayName(), savedIncident.getReporterDepartment(), savedIncident.getIssueType(),
                savedIncident.getSeverity(), savedIncident.getPriority(), savedIncident.getReportedAt(),
                savedIncident.getDescription(), savedIncident.getAssignedOwner(), savedIncident.getStatus(),
                savedIncident.getCreatedAt(), savedIncident.getCategory(), savedIncident.getAffectedSystem(),
                savedIncident.getImpactedUserOrDepartment(), responsibleDepartmentName));
        return toResponseDto(savedIncident);
    }

    @Override
    public IncidentResponseDto getIncident(Long id) {
        return secureRead(() -> {
        AppUser actor = getAuthenticatedUser();
        Incident incident = findIncident(id);
        ensureCanViewIncident(actor, incident, ReadOperation.DETAIL);
        return toResponseDto(incident);

        });
    }

    @Override
    public IncidentResponseDto getIncidentByNumber(String incidentNumber) {
        return secureRead(() -> {
        AppUser actor = getAuthenticatedUser();
        Incident incident = incidentRepository.findByIncidentNumber(incidentNumber)
                .orElseThrow(() -> new IncidentNotFoundException("Incident not found."));
        ensureCanViewIncident(actor, incident, ReadOperation.NUMBER_LOOKUP);
        return toResponseDto(incident);

        });
    }

    @Override
    public List<IncidentResponseDto> getAllIncidents() {
        return secureRead(() -> {
        AppUser actor = getAuthenticatedUser();
        List<Incident> incidents = incidentAccessEnabled
                ? listCandidates(actor,0,100)
                : actor.getRole() == AppUserRole.REPORTER
                  ? incidentRepository.findByReportedByIgnoreCaseOrderByCreatedAtDescIdDesc(actor.getEmail())
                  : incidentRepository.findAllByOrderByCreatedAtDescIdDesc();
        var visible = incidentAccessEnabled ? policyForRead().filterRead(actor,incidents,com.pareidolia.incidentmanagement.security.IncidentAccessPolicy.Permission.VIEW, ReadOperation.LIST) : legacyVisible(actor, incidents);
        var responses = visible.stream().map(incidentMapper::toResponseDto).toList();
        enrichAttention(responses);
        return responses;

        });
    }

    @Override
    @Transactional
    public IncidentResponseDto assignIncident(Long id, AssignIncidentRequestDto request) {
        if(employeeAssignmentEnabled)throw new AccessDeniedException("Use the employee assignment workflow.");
        securityWrite();
        AppUser actor = getAuthenticatedUser();
        requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        Incident incident = findIncident(id);
        requireMutation(actor,incident,com.pareidolia.incidentmanagement.security.IncidentAccessPolicy.Permission.ASSIGN);
        if (incidentAccessEnabled) requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        ensureNotClosed(incident, "assign");

        String oldOwner = incident.getAssignedOwner();
        incident.setAssignedOwner(request.getAssignedOwner());
        recordHistory(incident, HistoryActionType.OWNER_ASSIGNED, oldOwner, request.getAssignedOwner(),
                actor.getEmail(), request.getRemarks());

        if (incident.getStatus() == IncidentStatus.OPEN) {
            transitionStatus(incident, IncidentStatus.ASSIGNED, actor.getEmail(), request.getRemarks());
        }

        return toResponseDto(incidentRepository.saveAndFlush(incident));
    }

    @Override
    @Transactional
    public IncidentResponseDto updateInvestigation(Long id, UpdateInvestigationRequestDto request) {
        securityWrite();
        AppUser actor = getAuthenticatedUser();
        requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        Incident incident = findIncident(id);
        requireMutation(actor,incident,com.pareidolia.incidentmanagement.security.IncidentAccessPolicy.Permission.HANDLE);
        if (incidentAccessEnabled) requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        ensureNotClosed(incident, "update investigation for");

        String oldInvestigationDetails = incident.getInvestigationDetails();
        incident.setInvestigationDetails(request.getInvestigationDetails());
        incident.setRootCause(request.getRootCause());
        incident.setActionsTaken(request.getActionsTaken());
        incident.setContainmentAction(request.getContainmentAction());
        incident.setCorrectiveAction(request.getCorrectiveAction());
        recordHistory(incident, HistoryActionType.INVESTIGATION_UPDATED, oldInvestigationDetails,
                request.getInvestigationDetails(), actor.getEmail(), request.getRemarks());

        if (incident.getStatus() == IncidentStatus.OPEN || incident.getStatus() == IncidentStatus.ASSIGNED) {
            transitionStatus(incident, IncidentStatus.IN_PROGRESS, actor.getEmail(), request.getRemarks());
        }

        return toResponseDto(incidentRepository.saveAndFlush(incident));
    }

    @Override
    @Transactional
    public IncidentResponseDto reclassifyIncident(Long id, ReclassifyIncidentRequestDto request) {
        securityWrite();
        AppUser actor = getAuthenticatedUser();
        requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        Incident incident = findIncident(id);
        requireMutation(actor,incident,com.pareidolia.incidentmanagement.security.IncidentAccessPolicy.Permission.MODIFY);
        if (incidentAccessEnabled) requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        ensureNotClosed(incident, "reclassify");

        String oldIssueType = enumValue(incident.getIssueType());
        if (incident.getIssueType() == com.pareidolia.incidentmanagement.enums.IssueType.HR_ISSUE
                && request.getIssueType() != incident.getIssueType()) {
            throw new InvalidRequestException("An HR issue cannot be changed to another issue type.");
        }
        incident.setIssueType(request.getIssueType());
        if (incident.getIssueType() == com.pareidolia.incidentmanagement.enums.IssueType.HR_ISSUE
                && (!incidentAccessEnabled || !policyForRead().allowsHrOperations(actor, incident))) {
            throw new IncidentNotFoundException("Incident not found.");
        }
        recordHistory(incident, HistoryActionType.ISSUE_TYPE_CHANGED, oldIssueType, enumValue(request.getIssueType()),
                actor.getEmail(), request.getRemarks());

        return toResponseDto(incidentRepository.saveAndFlush(incident));
    }

    @Override
    @Transactional
    public IncidentResponseDto changeSeverity(Long id, ChangeSeverityRequestDto request) {
        securityWrite();
        AppUser actor = getAuthenticatedUser();
        requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        Incident incident = findIncident(id);
        requireMutation(actor,incident,com.pareidolia.incidentmanagement.security.IncidentAccessPolicy.Permission.MODIFY);
        if (incidentAccessEnabled) requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        ensureNotClosed(incident, "change severity for");

        String oldSeverity = enumValue(incident.getSeverity());
        incident.setSeverity(request.getSeverity());
        recordHistory(incident, HistoryActionType.SEVERITY_CHANGED, oldSeverity, enumValue(request.getSeverity()),
                actor.getEmail(), request.getRemarks());

        return toResponseDto(incidentRepository.saveAndFlush(incident));
    }

    @Override
    @Transactional
    public IncidentResponseDto changePriority(Long id, ChangePriorityRequestDto request) {
        securityWrite();
        AppUser actor = getAuthenticatedUser();
        requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        Incident incident = findIncident(id);
        requireMutation(actor,incident,com.pareidolia.incidentmanagement.security.IncidentAccessPolicy.Permission.MODIFY);
        if (incidentAccessEnabled) requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        ensureNotClosed(incident, "change priority for");

        String oldPriority = enumValue(incident.getPriority());
        incident.setPriority(request.getPriority());
        recordHistory(incident, HistoryActionType.PRIORITY_CHANGED, oldPriority, enumValue(request.getPriority()),
                actor.getEmail(), request.getRemarks());

        return toResponseDto(incidentRepository.saveAndFlush(incident));
    }

    @Override
    @Transactional
    public IncidentResponseDto escalateIncident(Long id, EscalateIncidentRequestDto request) {
        securityWrite();
        AppUser actor = getAuthenticatedUser();
        requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        Incident incident = findIncident(id);
        requireMutation(actor,incident,com.pareidolia.incidentmanagement.security.IncidentAccessPolicy.Permission.MODIFY);
        if (incidentAccessEnabled) requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        ensureNotClosed(incident, "escalate");

        String oldEscalationDetails = incident.getEscalationDetails();
        incident.setEscalationRequired(Boolean.TRUE);
        incident.setEscalationDetails(request.getEscalationDetails());
        recordHistory(incident, HistoryActionType.ESCALATED, oldEscalationDetails, request.getEscalationDetails(),
                actor.getEmail(), request.getRemarks());

        return toResponseDto(incidentRepository.saveAndFlush(incident));
    }

    @Override
    @Transactional
    public IncidentResponseDto updateEvidenceReference(Long id, UpdateEvidenceReferenceRequestDto request) {
        securityWrite();
        AppUser actor = getAuthenticatedUser();
        requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        Incident incident = findIncident(id);
        requireMutation(actor,incident,com.pareidolia.incidentmanagement.security.IncidentAccessPolicy.Permission.MODIFY);
        if (incidentAccessEnabled) requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        ensureNotClosed(incident, "update evidence for");

        String oldEvidenceReference = incident.getEvidenceReference();
        incident.setEvidenceReference(request.getEvidenceReference());
        recordHistory(incident, HistoryActionType.EVIDENCE_UPDATED, oldEvidenceReference, request.getEvidenceReference(),
                actor.getEmail(), request.getRemarks());

        return toResponseDto(incidentRepository.saveAndFlush(incident));
    }

    @Override
    @Transactional
    public IncidentResponseDto resolveIncident(Long id, ResolveIncidentRequestDto request) {
        securityWrite();
        AppUser actor = getAuthenticatedUser();
        requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        Incident incident = findIncident(id);
        requireMutation(actor,incident,com.pareidolia.incidentmanagement.security.IncidentAccessPolicy.Permission.HANDLE);
        if (incidentAccessEnabled) requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        requireStatus(incident, "resolve", IncidentStatus.ASSIGNED, IncidentStatus.IN_PROGRESS);

        String oldResolutionDetails = incident.getResolutionDetails();
        incident.setResolutionDetails(request.getResolutionDetails());
        incident.setResolvedAt(LocalDateTime.now());
        recordHistory(incident, HistoryActionType.INCIDENT_RESOLVED, oldResolutionDetails, request.getResolutionDetails(),
                actor.getEmail(), request.getRemarks());
        transitionStatus(incident, IncidentStatus.RESOLVED, actor.getEmail(), request.getRemarks());

        return toResponseDto(incidentRepository.saveAndFlush(incident));
    }

    @Override
    @Transactional
    public IncidentResponseDto validateIncident(Long id, ValidateIncidentRequestDto request) {
        securityWrite();
        AppUser actor = getAuthenticatedUser();
        Incident incident = findIncident(id);
        requireMutation(actor,incident,com.pareidolia.incidentmanagement.security.IncidentAccessPolicy.Permission.VIEW);
        requireOriginalReporter(actor, incident, "validate");
        requireStatus(incident, "validate", IncidentStatus.RESOLVED);

        String oldValidationDetails = incident.getValidationDetails();
        incident.setValidationDetails(request.getValidationDetails());
        incident.setValidatedBy(actor.getEmail());
        incident.setValidatedAt(LocalDateTime.now());
        recordHistory(incident, HistoryActionType.INCIDENT_VALIDATED, oldValidationDetails, request.getValidationDetails(),
                actor.getEmail(), request.getRemarks());
        transitionStatus(incident, IncidentStatus.VALIDATED, actor.getEmail(), request.getRemarks());

        return toResponseDto(incidentRepository.saveAndFlush(incident));
    }

    @Override
    @Transactional
    public IncidentResponseDto submitResolutionFeedback(Long id, ResolutionFeedbackRequestDto request) {
        securityWrite();
        AppUser actor = getAuthenticatedUser();
        Incident incident = findIncident(id);
        requireMutation(actor,incident,com.pareidolia.incidentmanagement.security.IncidentAccessPolicy.Permission.VIEW);
        requireOriginalReporter(actor, incident, "submit resolution feedback for");
        requireStatus(incident, "submit resolution feedback for", IncidentStatus.RESOLVED);

        String remarks = "Reporter feedback: " + request.getFeedback().trim();
        if (request.getEvidenceReference() != null && !request.getEvidenceReference().isBlank()) {
            remarks += "\nEvidence reference: " + request.getEvidenceReference().trim();
        }
        recordHistory(incident, HistoryActionType.RESOLUTION_NOT_ACCEPTED,
                IncidentStatus.RESOLVED.name(), IncidentStatus.IN_PROGRESS.name(), actor.getEmail(), remarks);
        transitionStatus(incident, IncidentStatus.IN_PROGRESS, actor.getEmail(), remarks);

        return toResponseDto(incidentRepository.saveAndFlush(incident));
    }

    @Override
    @Transactional
    public IncidentResponseDto closeIncident(Long id, CloseIncidentRequestDto request) {
        securityWrite();
        AppUser actor = getAuthenticatedUser();
        Incident incident = findIncident(id);
        requireMutation(actor,incident,com.pareidolia.incidentmanagement.security.IncidentAccessPolicy.Permission.VIEW);
        requireOriginalReporter(actor, incident, "close");
        requireStatus(incident, "close", IncidentStatus.VALIDATED);

        incident.setClosureConfirmedBy(actor.getEmail());
        incident.setClosedAt(LocalDateTime.now());
        recordHistory(incident, HistoryActionType.INCIDENT_CLOSED, null, IncidentStatus.CLOSED.name(),
                actor.getEmail(), request.getRemarks());
        transitionStatus(incident, IncidentStatus.CLOSED, actor.getEmail(), request.getRemarks());

        return toResponseDto(incidentRepository.saveAndFlush(incident));
    }

    @Override
    @Transactional
    public IncidentResponseDto reviewIncident(Long id, ReviewIncidentRequestDto request) {
        securityWrite();
        AppUser actor = getAuthenticatedUser();
        requireRole(actor, AppUserRole.REVIEWER, AppUserRole.ADMIN);
        Incident incident = findIncident(id);
        requireMutation(actor,incident,com.pareidolia.incidentmanagement.security.IncidentAccessPolicy.Permission.MODIFY);
        if (incidentAccessEnabled) requireRole(actor, AppUserRole.REVIEWER, AppUserRole.ADMIN);
        requireStatus(incident, "review", IncidentStatus.CLOSED);
        if (incident.getReviewedAt() != null) {
            throw new InvalidIncidentStateException("Incident has already been reviewed.");
        }

        String oldReviewDetails = incident.getReviewDetails();
        incident.setReviewDetails(request.getReviewDetails());
        incident.setReviewedBy(actor.getEmail());
        incident.setReviewedAt(LocalDateTime.now());
        if (request.getLessonsLearned() != null) {
            incident.setLessonsLearned(request.getLessonsLearned());
        }
        if (request.getPreventiveAction() != null) {
            incident.setPreventiveAction(request.getPreventiveAction());
        }
        recordHistory(incident, HistoryActionType.INCIDENT_REVIEWED, oldReviewDetails, request.getReviewDetails(),
                actor.getEmail(), request.getRemarks());

        return toResponseDto(incidentRepository.saveAndFlush(incident));
    }

    @Override
    public List<IncidentHistoryResponseDto> getIncidentHistory(Long id) {
        return secureRead(() -> {
        AppUser actor = getAuthenticatedUser();
        Incident incident = findIncident(id);
        ensureCanViewIncident(actor, incident, ReadOperation.HISTORY);
        return incidentHistoryRepository.findByIncidentIdOrderByChangedAtAscIdAsc(id).stream()
                .map(incidentMapper::toHistoryResponseDto)
                .toList();

        });
    }

    @Override
    @Transactional
    public IncidentResponseDto addWorkNote(Long id, AddWorkNoteRequestDto request) {
        securityWrite();
        AppUser actor = getAuthenticatedUser();
        requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        Incident incident = findIncident(id);
        requireMutation(actor,incident,com.pareidolia.incidentmanagement.security.IncidentAccessPolicy.Permission.HANDLE);
        if (incidentAccessEnabled) requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        ensureNotClosed(incident, "add a work note to");
        recordHistory(incident, HistoryActionType.WORK_NOTE, null, null,
                actor.getEmail(), request.remarks().trim());
        return toResponseDto(incident);
    }

    private IncidentResponseDto toResponseDto(Incident incident) {
        IncidentResponseDto dto = incidentMapper.toResponseDto(incident);
        if (incident.getResponsibleDepartmentId() != null) {
            incidentRepository.findActiveResponsibleDepartmentName(incident.getResponsibleDepartmentId())
                    .ifPresent(dto::setResponsibleDepartmentName);
        }
        enrichAttention(List.of(dto));
        return dto;
    }

    private void enrichAttention(List<IncidentResponseDto> responses) {
        if (responses.isEmpty()) return;
        var byId = responses.stream().collect(java.util.stream.Collectors.toMap(IncidentResponseDto::getId, d -> d));
        var events = incidentHistoryRepository.findLatestAttentionEvents(List.copyOf(byId.keySet()),
                List.of(HistoryActionType.RESOLUTION_NOT_ACCEPTED, HistoryActionType.INCIDENT_RESOLVED));
        for (IncidentHistory event : events) {
            var dto = byId.get(event.getIncident().getId());
            if (dto.getStatus() == IncidentStatus.IN_PROGRESS
                    && event.getActionType() == HistoryActionType.RESOLUTION_NOT_ACCEPTED) {
                dto.setIssueStillPersists(true);
                dto.setIssueStillPersistsAt(event.getChangedAt());
                dto.setIssueStillPersistsReportedBy(event.getChangedBy());
            }
        }
    }

    @Override
    public boolean departmentScopedIntakeAvailable() {
        return incidentAccessEnabled && employeeAssignmentEnabled && employeeAssignment != null;
    }

    private Incident findIncident(Long id) {
        return incidentRepository.findById(id)
                .orElseThrow(() -> new IncidentNotFoundException("Incident not found."));
    }

    private AppUser getAuthenticatedUser() {
        return appUserService.getAuthenticatedUser();
    }

    private void requireRole(AppUser appUser, AppUserRole... allowedRoles) {
        for (AppUserRole allowedRole : allowedRoles) {
            if (appUser.getRole() == allowedRole) {
                return;
            }
        }
        throw new AccessDeniedException("Access denied.");
    }

    private void requireOriginalReporter(AppUser actor, Incident incident, String action) {
        String actorEmail = actor == null || actor.getEmail() == null ? "" : actor.getEmail().trim();
        String reporterEmail = incident == null || incident.getReportedBy() == null ? "" : incident.getReportedBy().trim();
        if (actorEmail.isEmpty() || reporterEmail.isEmpty() || !actorEmail.equalsIgnoreCase(reporterEmail)) {
            throw new AccessDeniedException("Only the original reporter may " + action + " this incident.");
        }
    }

    private com.pareidolia.incidentmanagement.security.IncidentAccessPolicy policyForRead(){if(accessPolicy==null)throw new IllegalStateException("Security policy unavailable.");return accessPolicy;}
    private List<Incident> listCandidates(AppUser actor,int page,int size){
        var paging=org.springframework.data.domain.PageRequest.of(page,size);
        return actor.getRole()==AppUserRole.REPORTER && !(incidentAccessEnabled && policyForRead().hasGlobalView(actor))?incidentRepository.findByReportedByIgnoreCaseOrderByCreatedAtDescIdDesc(actor.getEmail(),paging):incidentRepository.findAllByOrderByCreatedAtDescIdDesc(paging);
    }
    @Override
    public List<IncidentResponseDto> getIncidentsPage(int page,int size){
        if(page<0 || page>100000 || size<1 || size>500)throw new com.pareidolia.incidentmanagement.exception.InvalidRequestException("Invalid incident page.");
        return secureRead(()->{var actor=getAuthenticatedUser();var candidates=listCandidates(actor,page,size);
            var visible=incidentAccessEnabled?policyForRead().filterRead(actor,candidates,com.pareidolia.incidentmanagement.security.IncidentAccessPolicy.Permission.VIEW, ReadOperation.LIST):legacyVisible(actor, candidates);
            var result=visible.stream().map(incidentMapper::toResponseDto).toList();enrichAttention(result);return result;});
    }
    private void requireProtected(AppUser actor, Incident incident, com.pareidolia.incidentmanagement.security.IncidentAccessPolicy.Permission permission) {
        boolean allowed = incidentAccessEnabled
                ? accessPolicy != null && accessPolicy.can(actor, incident, permission)
                : legacyVisible(actor, List.of(incident)).size() == 1;
        if (!allowed) throw new IncidentNotFoundException("Incident not found.");
    }
    private void requireMutation(AppUser actor,Incident incident,com.pareidolia.incidentmanagement.security.IncidentAccessPolicy.Permission permission) {
        if (incidentAccessEnabled) {
            if (accessPolicy == null || !accessPolicy.canForMutation(actor, incident, permission)) {
                throw new IncidentNotFoundException("Incident not found.");
            }
            return;
        }
        boolean persisted = IncidentConfidentiality.persistedRestrictions(List.of(incident), incidentRepository)
                .contains(incident.getId());
        boolean reporterAction = permission == com.pareidolia.incidentmanagement.security.IncidentAccessPolicy.Permission.VIEW
                && IncidentConfidentiality.isReporter(actor, incident);
        boolean denied = persisted
                ? !reporterAction || !IncidentConfidentiality.reporterMayViewRestricted(actor, incident, incidentRepository)
                : !reporterAction && (IncidentConfidentiality.requiresRestriction(incident, incidentRepository)
                    || (permission == com.pareidolia.incidentmanagement.security.IncidentAccessPolicy.Permission.ASSIGN
                        && incident.getResponsibleDepartmentId() != null));
        if (denied) throw new IncidentNotFoundException("Incident not found.");
    }
    private List<Incident> legacyVisible(AppUser actor, List<Incident> incidents) {
        var restricted = IncidentConfidentiality.persistedRestrictions(incidents, incidentRepository);
        return incidents.stream().filter(incident -> restricted.contains(incident.getId())
                ? IncidentConfidentiality.reporterMayViewRestricted(actor, incident, incidentRepository)
                : IncidentConfidentiality.isReporter(actor, incident)
                    || !IncidentConfidentiality.requiresRestriction(incident, incidentRepository)).toList();
    }

    private void ensureCanViewIncident(AppUser appUser, Incident incident, ReadOperation operation) {
        if (incidentAccessEnabled && policyForRead().useGlobalView(appUser, List.of(incident), operation)) return;
        requireProtected(appUser,incident,com.pareidolia.incidentmanagement.security.IncidentAccessPolicy.Permission.VIEW);
        if (appUser.getRole() == AppUserRole.REPORTER
                && !appUser.getEmail().equalsIgnoreCase(incident.getReportedBy())) {
            if (incidentAccessEnabled) throw new IncidentNotFoundException("Incident not found.");
            throw new AccessDeniedException("Access denied.");
        }
    }

    @Override
    public void checkAttachmentRead(Long incidentId, boolean download) {
        secureRead(() -> {
            ensureCanViewIncident(getAuthenticatedUser(), findIncident(incidentId),
                    download ? ReadOperation.ATTACHMENT_DOWNLOAD : ReadOperation.ATTACHMENT_LIST);
            return null;
        });
    }


    private String generateIncidentNumber() {
        String incidentNumber;

        do {
            LocalDateTime now = LocalDateTime.now();

            String suffix = UUID.randomUUID()
                    .toString()
                    .replace("-", "")
                    .substring(0, 8)
                    .toUpperCase(Locale.ROOT);

            incidentNumber = "INC-"
                    + INCIDENT_TIMESTAMP_FORMAT.format(now)
                    + "-"
                    + suffix;

        } while (incidentRepository.findByIncidentNumber(incidentNumber).isPresent());

        return incidentNumber;
    }


    private void ensureNotClosed(Incident incident, String operation) {
        if (incident.getStatus() == IncidentStatus.CLOSED) {
            throw new InvalidIncidentStateException("Cannot " + operation + " a closed incident.");
        }
    }

    private void requireStatus(Incident incident, String operation, IncidentStatus... allowedStatuses) {
        for (IncidentStatus allowedStatus : allowedStatuses) {
            if (incident.getStatus() == allowedStatus) {
                return;
            }
        }
        throw new InvalidIncidentStateException("Cannot " + operation + " incident in status " + incident.getStatus() + ".");
    }

    private void transitionStatus(Incident incident, IncidentStatus newStatus, String changedBy, String remarks) {
        IncidentStatus oldStatus = incident.getStatus();
        if (oldStatus == newStatus) {
            return;
        }
        incident.setStatus(newStatus);
        recordHistory(incident, HistoryActionType.STATUS_CHANGED, oldStatus.name(), newStatus.name(), changedBy, remarks);
    }

    private void recordHistory(
            Incident incident,
            HistoryActionType actionType,
            String oldValue,
            String newValue,
            String changedBy,
            String remarks
    ) {
        IncidentHistory history = new IncidentHistory();
        history.setIncident(incident);
        history.setActionType(actionType);
        history.setOldValue(oldValue);
        history.setNewValue(newValue);
        history.setChangedBy(changedBy);
        history.setRemarks(remarks);
        incidentHistoryRepository.save(history);
    }

    private String enumValue(Enum<?> value) {
        return value == null ? null : value.name();
    }
}
