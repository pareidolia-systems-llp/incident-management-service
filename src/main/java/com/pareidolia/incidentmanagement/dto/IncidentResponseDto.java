package com.pareidolia.incidentmanagement.dto;

import com.pareidolia.incidentmanagement.enums.IncidentStatus;
import com.pareidolia.incidentmanagement.enums.IssueType;
import com.pareidolia.incidentmanagement.enums.Priority;
import com.pareidolia.incidentmanagement.enums.Severity;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
public class IncidentResponseDto {

    private Long id;
    private String incidentNumber;
    private LocalDateTime reportedAt;
    private String reportedBy;
    private String reporterDepartment;
    private String deskNumber;
    private String title;
    private String description;
    private IssueType issueType;
    private String category;
    private String affectedSystem;
    private String impactedUserOrDepartment;
    private Severity severity;
    private Priority priority;
    private String assignedOwner;
    private IncidentStatus status;
    private String investigationDetails;
    private String rootCause;
    private String actionsTaken;
    private String containmentAction;
    private String correctiveAction;
    private Boolean escalationRequired;
    private String escalationDetails;
    private String resolutionDetails;
    private LocalDateTime resolvedAt;
    private String validationDetails;
    private String validatedBy;
    private LocalDateTime validatedAt;
    private String closureConfirmedBy;
    private LocalDateTime closedAt;
    private String evidenceReference;
    private String lessonsLearned;
    private String preventiveAction;
    private String reviewDetails;
    private String reviewedBy;
    private LocalDateTime reviewedAt;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
