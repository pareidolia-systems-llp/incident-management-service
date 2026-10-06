package com.pareidolia.incidentmanagement.entity;

import com.pareidolia.incidentmanagement.enums.IncidentStatus;
import com.pareidolia.incidentmanagement.enums.IssueType;
import com.pareidolia.incidentmanagement.enums.Priority;
import com.pareidolia.incidentmanagement.enums.Severity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Table(name = "incidents", indexes = {
        @Index(name = "idx_incidents_status", columnList = "status"),
        @Index(name = "idx_incidents_issue_type", columnList = "issue_type"),
        @Index(name = "idx_incidents_severity_priority", columnList = "severity, priority"),
        @Index(name = "idx_incidents_assigned_owner", columnList = "assigned_owner"),
        @Index(name = "idx_incidents_reported_at", columnList = "reported_at"),
        @Index(name = "idx_incidents_resolved_at", columnList = "resolved_at")
})
@Getter
@Setter
@NoArgsConstructor
public class Incident {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Size(max = 50)
    @Column(name = "incident_number", nullable = false, unique = true, length = 50)
    private String incidentNumber;

    @NotNull
    @Column(name = "reported_at", nullable = false)
    private LocalDateTime reportedAt;

    @NotBlank
    @Size(max = 150)
    @Column(name = "reported_by", nullable = false, length = 150)
    private String reportedBy;

    @Size(max = 150)
    @Column(name = "reporter_department", length = 150)
    private String reporterDepartment;

    @Size(max = 255)
    @Column(name = "desk_number", length = 255)
    private String deskNumber;

    @NotBlank
    @Size(max = 255)
    @Column(nullable = false, length = 255)
    private String title;

    @NotBlank
    @Column(nullable = false, columnDefinition = "TEXT")
    private String description;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(name = "issue_type", nullable = false, length = 50)
    private IssueType issueType;

    @Size(max = 100)
    @Column(length = 100)
    private String category;

    @Size(max = 255)
    @Column(name = "affected_system", length = 255)
    private String affectedSystem;

    @Size(max = 255)
    @Column(name = "impacted_user_or_department", length = 255)
    private String impactedUserOrDepartment;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Severity severity;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Priority priority;

    @Size(max = 150)
    @Column(name = "assigned_owner", length = 150)
    private String assignedOwner;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private IncidentStatus status = IncidentStatus.OPEN;

    @Column(name = "investigation_details", columnDefinition = "TEXT")
    private String investigationDetails;

    @Column(name = "root_cause", columnDefinition = "TEXT")
    private String rootCause;

    @Column(name = "actions_taken", columnDefinition = "TEXT")
    private String actionsTaken;

    @Column(name = "containment_action", columnDefinition = "TEXT")
    private String containmentAction;

    @Column(name = "corrective_action", columnDefinition = "TEXT")
    private String correctiveAction;

    @NotNull
    @Column(name = "escalation_required", nullable = false)
    private Boolean escalationRequired = Boolean.FALSE;

    @Column(name = "escalation_details", columnDefinition = "TEXT")
    private String escalationDetails;

    @Column(name = "resolution_details", columnDefinition = "TEXT")
    private String resolutionDetails;

    @Column(name = "resolved_at")
    private LocalDateTime resolvedAt;

    @Column(name = "validation_details", columnDefinition = "TEXT")
    private String validationDetails;

    @Size(max = 150)
    @Column(name = "validated_by", length = 150)
    private String validatedBy;

    @Column(name = "validated_at")
    private LocalDateTime validatedAt;

    @Size(max = 150)
    @Column(name = "closure_confirmed_by", length = 150)
    private String closureConfirmedBy;

    @Column(name = "closed_at")
    private LocalDateTime closedAt;

    @Column(name = "review_details", columnDefinition = "TEXT")
    private String reviewDetails;

    @Size(max = 150)
    @Column(name = "reviewed_by", length = 150)
    private String reviewedBy;

    @Column(name = "reviewed_at")
    private LocalDateTime reviewedAt;

    @Size(max = 500)
    @Column(name = "evidence_reference", length = 500)
    private String evidenceReference;

    @Column(name = "lessons_learned", columnDefinition = "TEXT")
    private String lessonsLearned;

    @Column(name = "preventive_action", columnDefinition = "TEXT")
    private String preventiveAction;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        if (reportedAt == null) {
            reportedAt = now;
        }
        createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
