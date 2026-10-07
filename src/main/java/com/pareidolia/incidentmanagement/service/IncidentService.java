package com.pareidolia.incidentmanagement.service;

import com.pareidolia.incidentmanagement.dto.AssignIncidentRequestDto;
import com.pareidolia.incidentmanagement.dto.ChangePriorityRequestDto;
import com.pareidolia.incidentmanagement.dto.ChangeSeverityRequestDto;
import com.pareidolia.incidentmanagement.dto.CloseIncidentRequestDto;
import com.pareidolia.incidentmanagement.dto.CreateIncidentRequestDto;
import com.pareidolia.incidentmanagement.dto.EscalateIncidentRequestDto;
import com.pareidolia.incidentmanagement.dto.IncidentHistoryResponseDto;
import com.pareidolia.incidentmanagement.dto.IncidentResponseDto;
import com.pareidolia.incidentmanagement.dto.ReclassifyIncidentRequestDto;
import com.pareidolia.incidentmanagement.dto.ResolveIncidentRequestDto;
import com.pareidolia.incidentmanagement.dto.ResolutionFeedbackRequestDto;
import com.pareidolia.incidentmanagement.dto.ReviewIncidentRequestDto;
import com.pareidolia.incidentmanagement.dto.UpdateEvidenceReferenceRequestDto;
import com.pareidolia.incidentmanagement.dto.UpdateInvestigationRequestDto;
import com.pareidolia.incidentmanagement.dto.ValidateIncidentRequestDto;

import java.util.List;

public interface IncidentService {

    IncidentResponseDto createIncident(CreateIncidentRequestDto request);

    IncidentResponseDto getIncident(Long id);

    IncidentResponseDto getIncidentByNumber(String incidentNumber);

    List<IncidentResponseDto> getAllIncidents();

    IncidentResponseDto assignIncident(Long id, AssignIncidentRequestDto request);

    IncidentResponseDto updateInvestigation(Long id, UpdateInvestigationRequestDto request);

    IncidentResponseDto reclassifyIncident(Long id, ReclassifyIncidentRequestDto request);

    IncidentResponseDto changeSeverity(Long id, ChangeSeverityRequestDto request);

    IncidentResponseDto changePriority(Long id, ChangePriorityRequestDto request);

    IncidentResponseDto escalateIncident(Long id, EscalateIncidentRequestDto request);

    IncidentResponseDto updateEvidenceReference(Long id, UpdateEvidenceReferenceRequestDto request);

    IncidentResponseDto resolveIncident(Long id, ResolveIncidentRequestDto request);

    IncidentResponseDto validateIncident(Long id, ValidateIncidentRequestDto request);

    IncidentResponseDto submitResolutionFeedback(Long id, ResolutionFeedbackRequestDto request);

    IncidentResponseDto closeIncident(Long id, CloseIncidentRequestDto request);

    IncidentResponseDto reviewIncident(Long id, ReviewIncidentRequestDto request);

    List<IncidentHistoryResponseDto> getIncidentHistory(Long id);
}
