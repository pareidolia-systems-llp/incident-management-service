package com.pareidolia.incidentmanagement.controller;

import com.pareidolia.incidentmanagement.dto.*;
import com.pareidolia.incidentmanagement.service.IncidentService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/incidents")
@RequiredArgsConstructor
public class IncidentController {

    private final IncidentService incidentService;

    @PostMapping
    public ResponseEntity<IncidentResponseDto> createIncident(@Valid @RequestBody CreateIncidentRequestDto request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(incidentService.createIncident(request));
    }

    @GetMapping
    public ResponseEntity<List<IncidentResponseDto>> getAllIncidents() {
        return ResponseEntity.ok(incidentService.getAllIncidents());
    }

    @GetMapping("/{id}")
    public ResponseEntity<IncidentResponseDto> getIncident(@PathVariable Long id) {
        return ResponseEntity.ok(incidentService.getIncident(id));
    }

    @GetMapping("/number/{incidentNumber}")
    public ResponseEntity<IncidentResponseDto> getIncidentByNumber(@PathVariable String incidentNumber) {
        return ResponseEntity.ok(incidentService.getIncidentByNumber(incidentNumber));
    }

    @GetMapping("/{id}/history")
    public ResponseEntity<List<IncidentHistoryResponseDto>> getIncidentHistory(@PathVariable Long id) {
        return ResponseEntity.ok(incidentService.getIncidentHistory(id));
    }

    @PostMapping("/{id}/assign")
    public ResponseEntity<IncidentResponseDto> assignIncident(
            @PathVariable Long id,
            @Valid @RequestBody AssignIncidentRequestDto request
    ) {
        return ResponseEntity.ok(incidentService.assignIncident(id, request));
    }

    @PostMapping("/{id}/investigation")
    public ResponseEntity<IncidentResponseDto> updateInvestigation(
            @PathVariable Long id,
            @Valid @RequestBody UpdateInvestigationRequestDto request
    ) {
        return ResponseEntity.ok(incidentService.updateInvestigation(id, request));
    }

    @PostMapping("/{id}/reclassify")
    public ResponseEntity<IncidentResponseDto> reclassifyIncident(
            @PathVariable Long id,
            @Valid @RequestBody ReclassifyIncidentRequestDto request
    ) {
        return ResponseEntity.ok(incidentService.reclassifyIncident(id, request));
    }

    @PostMapping("/{id}/severity")
    public ResponseEntity<IncidentResponseDto> changeSeverity(
            @PathVariable Long id,
            @Valid @RequestBody ChangeSeverityRequestDto request
    ) {
        return ResponseEntity.ok(incidentService.changeSeverity(id, request));
    }

    @PostMapping("/{id}/priority")
    public ResponseEntity<IncidentResponseDto> changePriority(
            @PathVariable Long id,
            @Valid @RequestBody ChangePriorityRequestDto request
    ) {
        return ResponseEntity.ok(incidentService.changePriority(id, request));
    }

    @PostMapping("/{id}/escalate")
    public ResponseEntity<IncidentResponseDto> escalateIncident(
            @PathVariable Long id,
            @Valid @RequestBody EscalateIncidentRequestDto request
    ) {
        return ResponseEntity.ok(incidentService.escalateIncident(id, request));
    }

    @PostMapping("/{id}/evidence")
    public ResponseEntity<IncidentResponseDto> updateEvidenceReference(
            @PathVariable Long id,
            @Valid @RequestBody UpdateEvidenceReferenceRequestDto request
    ) {
        return ResponseEntity.ok(incidentService.updateEvidenceReference(id, request));
    }

    @PostMapping("/{id}/resolve")
    public ResponseEntity<IncidentResponseDto> resolveIncident(
            @PathVariable Long id,
            @Valid @RequestBody ResolveIncidentRequestDto request
    ) {
        return ResponseEntity.ok(incidentService.resolveIncident(id, request));
    }

    @PostMapping("/{id}/validate")
    public ResponseEntity<IncidentResponseDto> validateIncident(
            @PathVariable Long id,
            @Valid @RequestBody ValidateIncidentRequestDto request
    ) {
        return ResponseEntity.ok(incidentService.validateIncident(id, request));
    }

    @PostMapping("/{id}/close")
    public ResponseEntity<IncidentResponseDto> closeIncident(
            @PathVariable Long id,
            @Valid @RequestBody CloseIncidentRequestDto request
    ) {
        return ResponseEntity.ok(incidentService.closeIncident(id, request));
    }

    @PostMapping("/{id}/resolution-feedback")
    public ResponseEntity<IncidentResponseDto> submitResolutionFeedback(
            @PathVariable Long id,
            @Valid @RequestBody ResolutionFeedbackRequestDto request
    ) {
        return ResponseEntity.ok(incidentService.submitResolutionFeedback(id, request));
    }

    @PostMapping("/{id}/review")
    public ResponseEntity<IncidentResponseDto> reviewIncident(
            @PathVariable Long id,
            @Valid @RequestBody ReviewIncidentRequestDto request
    ) {
        return ResponseEntity.ok(incidentService.reviewIncident(id, request));
    }
}
