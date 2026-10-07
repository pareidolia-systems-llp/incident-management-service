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
import com.pareidolia.incidentmanagement.mapper.IncidentMapper;
import com.pareidolia.incidentmanagement.repository.IncidentHistoryRepository;
import com.pareidolia.incidentmanagement.repository.IncidentRepository;
import com.pareidolia.incidentmanagement.service.IncidentService;
import com.pareidolia.incidentmanagement.service.AppUserService;
import org.springframework.beans.factory.annotation.Value;
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

    private static final String SYSTEM_ACTOR = "SYSTEM";
    private static final DateTimeFormatter INCIDENT_YEAR_FORMAT = DateTimeFormatter.ofPattern("yyyy");
    private static final DateTimeFormatter INCIDENT_TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");

    private final IncidentRepository incidentRepository;
    private final IncidentHistoryRepository incidentHistoryRepository;
    private final IncidentMapper incidentMapper;
    private final AppUserService appUserService;
    private final String defaultItOwner;

    public IncidentServiceImpl(
            IncidentRepository incidentRepository,
            IncidentHistoryRepository incidentHistoryRepository,
            IncidentMapper incidentMapper,
            AppUserService appUserService,
            @Value("${app.default-it-owner}") String defaultItOwner
    ) {
        this.incidentRepository = incidentRepository;
        this.incidentHistoryRepository = incidentHistoryRepository;
        this.incidentMapper = incidentMapper;
        this.appUserService = appUserService;
        this.defaultItOwner = defaultItOwner.trim();
    }

    @Override
    @Transactional
    public IncidentResponseDto createIncident(CreateIncidentRequestDto request) {
        AppUser actor = getAuthenticatedUser();
        requireRole(actor, AppUserRole.REPORTER, AppUserRole.ADMIN);

        Incident incident = incidentMapper.toEntity(request);
        incident.setReportedBy(actor.getEmail());
        incident.setIncidentNumber(generateIncidentNumber());
        incident.setAssignedOwner(defaultItOwner);
        incident.setStatus(IncidentStatus.ASSIGNED);

        Incident savedIncident = incidentRepository.save(incident);
        recordHistory(
                savedIncident,
                HistoryActionType.INCIDENT_CREATED,
                null,
                savedIncident.getIncidentNumber(),
                actor.getEmail(),
                null
        );
        recordHistory(
                savedIncident,
                HistoryActionType.OWNER_ASSIGNED,
                null,
                savedIncident.getAssignedOwner(),
                SYSTEM_ACTOR,
                "Automatically assigned to the configured default IT owner."
        );
        return incidentMapper.toResponseDto(savedIncident);
    }

    @Override
    @Transactional(readOnly = true)
    public IncidentResponseDto getIncident(Long id) {
        AppUser actor = getAuthenticatedUser();
        Incident incident = findIncident(id);
        ensureCanViewIncident(actor, incident);
        return incidentMapper.toResponseDto(incident);
    }

    @Override
    @Transactional(readOnly = true)
    public IncidentResponseDto getIncidentByNumber(String incidentNumber) {
        AppUser actor = getAuthenticatedUser();
        Incident incident = incidentRepository.findByIncidentNumber(incidentNumber)
                .orElseThrow(() -> new IncidentNotFoundException("Incident not found with number: " + incidentNumber));
        ensureCanViewIncident(actor, incident);
        return incidentMapper.toResponseDto(incident);
    }

    @Override
    @Transactional(readOnly = true)
    public List<IncidentResponseDto> getAllIncidents() {
        AppUser actor = getAuthenticatedUser();
        List<Incident> incidents = actor.getRole() == AppUserRole.REPORTER
                ? incidentRepository.findByReportedByIgnoreCaseOrderByCreatedAtDescIdDesc(actor.getEmail())
                : incidentRepository.findAllByOrderByCreatedAtDescIdDesc();
        return incidents.stream()
                .map(incidentMapper::toResponseDto)
                .toList();
    }

    @Override
    @Transactional
    public IncidentResponseDto assignIncident(Long id, AssignIncidentRequestDto request) {
        AppUser actor = getAuthenticatedUser();
        requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        Incident incident = findIncident(id);
        ensureNotClosed(incident, "assign");

        String oldOwner = incident.getAssignedOwner();
        incident.setAssignedOwner(request.getAssignedOwner());
        recordHistory(incident, HistoryActionType.OWNER_ASSIGNED, oldOwner, request.getAssignedOwner(),
                actor.getEmail(), request.getRemarks());

        if (incident.getStatus() == IncidentStatus.OPEN) {
            transitionStatus(incident, IncidentStatus.ASSIGNED, actor.getEmail(), request.getRemarks());
        }

        return incidentMapper.toResponseDto(incidentRepository.saveAndFlush(incident));
    }

    @Override
    @Transactional
    public IncidentResponseDto updateInvestigation(Long id, UpdateInvestigationRequestDto request) {
        AppUser actor = getAuthenticatedUser();
        requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        Incident incident = findIncident(id);
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

        return incidentMapper.toResponseDto(incidentRepository.saveAndFlush(incident));
    }

    @Override
    @Transactional
    public IncidentResponseDto reclassifyIncident(Long id, ReclassifyIncidentRequestDto request) {
        AppUser actor = getAuthenticatedUser();
        requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        Incident incident = findIncident(id);
        ensureNotClosed(incident, "reclassify");

        String oldIssueType = enumValue(incident.getIssueType());
        incident.setIssueType(request.getIssueType());
        recordHistory(incident, HistoryActionType.ISSUE_TYPE_CHANGED, oldIssueType, enumValue(request.getIssueType()),
                actor.getEmail(), request.getRemarks());

        return incidentMapper.toResponseDto(incidentRepository.saveAndFlush(incident));
    }

    @Override
    @Transactional
    public IncidentResponseDto changeSeverity(Long id, ChangeSeverityRequestDto request) {
        AppUser actor = getAuthenticatedUser();
        requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        Incident incident = findIncident(id);
        ensureNotClosed(incident, "change severity for");

        String oldSeverity = enumValue(incident.getSeverity());
        incident.setSeverity(request.getSeverity());
        recordHistory(incident, HistoryActionType.SEVERITY_CHANGED, oldSeverity, enumValue(request.getSeverity()),
                actor.getEmail(), request.getRemarks());

        return incidentMapper.toResponseDto(incidentRepository.saveAndFlush(incident));
    }

    @Override
    @Transactional
    public IncidentResponseDto changePriority(Long id, ChangePriorityRequestDto request) {
        AppUser actor = getAuthenticatedUser();
        requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        Incident incident = findIncident(id);
        ensureNotClosed(incident, "change priority for");

        String oldPriority = enumValue(incident.getPriority());
        incident.setPriority(request.getPriority());
        recordHistory(incident, HistoryActionType.PRIORITY_CHANGED, oldPriority, enumValue(request.getPriority()),
                actor.getEmail(), request.getRemarks());

        return incidentMapper.toResponseDto(incidentRepository.saveAndFlush(incident));
    }

    @Override
    @Transactional
    public IncidentResponseDto escalateIncident(Long id, EscalateIncidentRequestDto request) {
        AppUser actor = getAuthenticatedUser();
        requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        Incident incident = findIncident(id);
        ensureNotClosed(incident, "escalate");

        String oldEscalationDetails = incident.getEscalationDetails();
        incident.setEscalationRequired(Boolean.TRUE);
        incident.setEscalationDetails(request.getEscalationDetails());
        recordHistory(incident, HistoryActionType.ESCALATED, oldEscalationDetails, request.getEscalationDetails(),
                actor.getEmail(), request.getRemarks());

        return incidentMapper.toResponseDto(incidentRepository.saveAndFlush(incident));
    }

    @Override
    @Transactional
    public IncidentResponseDto updateEvidenceReference(Long id, UpdateEvidenceReferenceRequestDto request) {
        AppUser actor = getAuthenticatedUser();
        requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        Incident incident = findIncident(id);
        ensureNotClosed(incident, "update evidence for");

        String oldEvidenceReference = incident.getEvidenceReference();
        incident.setEvidenceReference(request.getEvidenceReference());
        recordHistory(incident, HistoryActionType.EVIDENCE_UPDATED, oldEvidenceReference, request.getEvidenceReference(),
                actor.getEmail(), request.getRemarks());

        return incidentMapper.toResponseDto(incidentRepository.saveAndFlush(incident));
    }

    @Override
    @Transactional
    public IncidentResponseDto resolveIncident(Long id, ResolveIncidentRequestDto request) {
        AppUser actor = getAuthenticatedUser();
        requireRole(actor, AppUserRole.IT_HANDLER, AppUserRole.ADMIN);
        Incident incident = findIncident(id);
        requireStatus(incident, "resolve", IncidentStatus.ASSIGNED, IncidentStatus.IN_PROGRESS);

        String oldResolutionDetails = incident.getResolutionDetails();
        incident.setResolutionDetails(request.getResolutionDetails());
        incident.setResolvedAt(LocalDateTime.now());
        recordHistory(incident, HistoryActionType.INCIDENT_RESOLVED, oldResolutionDetails, request.getResolutionDetails(),
                actor.getEmail(), request.getRemarks());
        transitionStatus(incident, IncidentStatus.RESOLVED, actor.getEmail(), request.getRemarks());

        return incidentMapper.toResponseDto(incidentRepository.saveAndFlush(incident));
    }

    @Override
    @Transactional
    public IncidentResponseDto validateIncident(Long id, ValidateIncidentRequestDto request) {
        AppUser actor = getAuthenticatedUser();
        Incident incident = findIncident(id);
        requireOriginalReporter(actor, incident, "validate");
        requireStatus(incident, "validate", IncidentStatus.RESOLVED);

        String oldValidationDetails = incident.getValidationDetails();
        incident.setValidationDetails(request.getValidationDetails());
        incident.setValidatedBy(actor.getEmail());
        incident.setValidatedAt(LocalDateTime.now());
        recordHistory(incident, HistoryActionType.INCIDENT_VALIDATED, oldValidationDetails, request.getValidationDetails(),
                actor.getEmail(), request.getRemarks());
        transitionStatus(incident, IncidentStatus.VALIDATED, actor.getEmail(), request.getRemarks());

        return incidentMapper.toResponseDto(incidentRepository.saveAndFlush(incident));
    }

    @Override
    @Transactional
    public IncidentResponseDto submitResolutionFeedback(Long id, ResolutionFeedbackRequestDto request) {
        AppUser actor = getAuthenticatedUser();
        Incident incident = findIncident(id);
        requireOriginalReporter(actor, incident, "submit resolution feedback for");
        requireStatus(incident, "submit resolution feedback for", IncidentStatus.RESOLVED);

        String remarks = "Reporter feedback: " + request.getFeedback().trim();
        if (request.getEvidenceReference() != null && !request.getEvidenceReference().isBlank()) {
            remarks += "\nEvidence reference: " + request.getEvidenceReference().trim();
        }
        recordHistory(incident, HistoryActionType.RESOLUTION_NOT_ACCEPTED,
                IncidentStatus.RESOLVED.name(), IncidentStatus.IN_PROGRESS.name(), actor.getEmail(), remarks);
        transitionStatus(incident, IncidentStatus.IN_PROGRESS, actor.getEmail(), remarks);

        return incidentMapper.toResponseDto(incidentRepository.saveAndFlush(incident));
    }

    @Override
    @Transactional
    public IncidentResponseDto closeIncident(Long id, CloseIncidentRequestDto request) {
        AppUser actor = getAuthenticatedUser();
        Incident incident = findIncident(id);
        requireOriginalReporter(actor, incident, "close");
        requireStatus(incident, "close", IncidentStatus.VALIDATED);

        incident.setClosureConfirmedBy(actor.getEmail());
        incident.setClosedAt(LocalDateTime.now());
        recordHistory(incident, HistoryActionType.INCIDENT_CLOSED, null, IncidentStatus.CLOSED.name(),
                actor.getEmail(), request.getRemarks());
        transitionStatus(incident, IncidentStatus.CLOSED, actor.getEmail(), request.getRemarks());

        return incidentMapper.toResponseDto(incidentRepository.saveAndFlush(incident));
    }

    @Override
    @Transactional
    public IncidentResponseDto reviewIncident(Long id, ReviewIncidentRequestDto request) {
        AppUser actor = getAuthenticatedUser();
        requireRole(actor, AppUserRole.REVIEWER, AppUserRole.ADMIN);
        Incident incident = findIncident(id);
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

        return incidentMapper.toResponseDto(incidentRepository.saveAndFlush(incident));
    }

    @Override
    @Transactional(readOnly = true)
    public List<IncidentHistoryResponseDto> getIncidentHistory(Long id) {
        AppUser actor = getAuthenticatedUser();
        Incident incident = findIncident(id);
        ensureCanViewIncident(actor, incident);
        return incidentHistoryRepository.findByIncidentIdOrderByChangedAtDesc(id).stream()
                .map(incidentMapper::toHistoryResponseDto)
                .toList();
    }

    private Incident findIncident(Long id) {
        return incidentRepository.findById(id)
                .orElseThrow(() -> new IncidentNotFoundException("Incident not found with id: " + id));
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

    private void ensureCanViewIncident(AppUser appUser, Incident incident) {
        if (appUser.getRole() == AppUserRole.REPORTER
                && !appUser.getEmail().equalsIgnoreCase(incident.getReportedBy())) {
            throw new AccessDeniedException("Access denied.");
        }
    }

    private String generateIncidentNumber() {
        String incidentNumber;
        do {
            LocalDateTime now = LocalDateTime.now();
            String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 8).toUpperCase(Locale.ROOT);
            incidentNumber = "INC-" + INCIDENT_YEAR_FORMAT.format(now) + "-"
                    + INCIDENT_TIMESTAMP_FORMAT.format(now) + "-" + suffix;
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
