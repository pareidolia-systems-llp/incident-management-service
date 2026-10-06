package com.pareidolia.incidentmanagement.mapper;

import com.pareidolia.incidentmanagement.dto.CreateIncidentRequestDto;
import com.pareidolia.incidentmanagement.dto.IncidentHistoryResponseDto;
import com.pareidolia.incidentmanagement.dto.IncidentResponseDto;
import com.pareidolia.incidentmanagement.entity.Incident;
import com.pareidolia.incidentmanagement.entity.IncidentHistory;
import org.springframework.stereotype.Component;

@Component
public class IncidentMapper {

    public Incident toEntity(CreateIncidentRequestDto dto) {
        if (dto == null) {
            return null;
        }

        Incident incident = new Incident();
        incident.setReporterDepartment(dto.getReporterDepartment());
        incident.setDeskNumber(dto.getDeskNumber());
        incident.setTitle(dto.getTitle());
        incident.setDescription(dto.getDescription());
        incident.setIssueType(dto.getIssueType());
        incident.setCategory(dto.getCategory());
        incident.setAffectedSystem(dto.getAffectedSystem());
        incident.setImpactedUserOrDepartment(dto.getImpactedUserOrDepartment());
        incident.setSeverity(dto.getSeverity());
        incident.setPriority(dto.getPriority());
        return incident;
    }

    public IncidentResponseDto toResponseDto(Incident incident) {
        if (incident == null) {
            return null;
        }

        IncidentResponseDto dto = new IncidentResponseDto();
        dto.setId(incident.getId());
        dto.setIncidentNumber(incident.getIncidentNumber());
        dto.setReportedAt(incident.getReportedAt());
        dto.setReportedBy(incident.getReportedBy());
        dto.setReporterDepartment(incident.getReporterDepartment());
        dto.setDeskNumber(incident.getDeskNumber());
        dto.setTitle(incident.getTitle());
        dto.setDescription(incident.getDescription());
        dto.setIssueType(incident.getIssueType());
        dto.setCategory(incident.getCategory());
        dto.setAffectedSystem(incident.getAffectedSystem());
        dto.setImpactedUserOrDepartment(incident.getImpactedUserOrDepartment());
        dto.setSeverity(incident.getSeverity());
        dto.setPriority(incident.getPriority());
        dto.setAssignedOwner(incident.getAssignedOwner());
        dto.setStatus(incident.getStatus());
        dto.setInvestigationDetails(incident.getInvestigationDetails());
        dto.setRootCause(incident.getRootCause());
        dto.setActionsTaken(incident.getActionsTaken());
        dto.setContainmentAction(incident.getContainmentAction());
        dto.setCorrectiveAction(incident.getCorrectiveAction());
        dto.setEscalationRequired(incident.getEscalationRequired());
        dto.setEscalationDetails(incident.getEscalationDetails());
        dto.setResolutionDetails(incident.getResolutionDetails());
        dto.setResolvedAt(incident.getResolvedAt());
        dto.setValidationDetails(incident.getValidationDetails());
        dto.setValidatedBy(incident.getValidatedBy());
        dto.setValidatedAt(incident.getValidatedAt());
        dto.setClosureConfirmedBy(incident.getClosureConfirmedBy());
        dto.setClosedAt(incident.getClosedAt());
        dto.setEvidenceReference(incident.getEvidenceReference());
        dto.setLessonsLearned(incident.getLessonsLearned());
        dto.setPreventiveAction(incident.getPreventiveAction());
        dto.setReviewDetails(incident.getReviewDetails());
        dto.setReviewedBy(incident.getReviewedBy());
        dto.setReviewedAt(incident.getReviewedAt());
        dto.setCreatedAt(incident.getCreatedAt());
        dto.setUpdatedAt(incident.getUpdatedAt());
        return dto;
    }

    public IncidentHistoryResponseDto toHistoryResponseDto(IncidentHistory history) {
        if (history == null) {
            return null;
        }

        IncidentHistoryResponseDto dto = new IncidentHistoryResponseDto();
        dto.setId(history.getId());
        dto.setActionType(history.getActionType());
        dto.setOldValue(history.getOldValue());
        dto.setNewValue(history.getNewValue());
        dto.setChangedBy(history.getChangedBy());
        dto.setRemarks(history.getRemarks());
        dto.setChangedAt(history.getChangedAt());
        return dto;
    }
}
