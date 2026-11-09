package com.pareidolia.incidentmanagement.dto;

import com.pareidolia.incidentmanagement.enums.IssueType;
import com.pareidolia.incidentmanagement.enums.Priority;
import com.pareidolia.incidentmanagement.enums.Severity;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import com.fasterxml.jackson.annotation.JsonSetter;
import tools.jackson.databind.JsonNode;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class CreateIncidentRequestDto {

    @Size(max = 150)
    private String reporterDepartment;

    @Positive
    private Long proposedHandlerUserId;

    @Positive
    private Long responsibleDepartmentId;

    @JsonSetter("responsibleDepartmentId")
    public void readResponsibleDepartmentId(JsonNode value) {
        if (value == null || value.isNull()) {
            responsibleDepartmentId = null;
            return;
        }
        if (!value.isIntegralNumber() || !value.canConvertToLong()) {
            throw new IllegalArgumentException("Responsible department ID must be an integer.");
        }
        responsibleDepartmentId = value.longValue();
    }

    @Size(max = 255)
    private String deskNumber;

    @NotBlank
    @Size(max = 255)
    private String title;

    @NotBlank
    @Size(max = 65535)
    private String description;

    @NotNull
    private IssueType issueType;

    @Size(max = 100)
    @Pattern(regexp = "(?:|Network / Connectivity|Account / Access|Hardware|Software / Application|Email / Collaboration|Device / Peripheral|Other"
            + "|Server / Infrastructure|Database|Security / Endpoint"
            + "|Account / Access Request|Software Installation|Hardware Request|Permission / Access Change|General IT Request|Routine HR Request"
            + "|Phishing / Suspicious Email|Suspicious Login / Account Activity|Malware / Suspicious File|Unauthorized Access|Data Leakage / Exposure|Lost / Stolen Device"
            + "|Account Compromise|Malware|Data Breach / Exposure|Policy Violation|Security Control Failure"
            + "|Ransomware|Major Data Breach|Critical System Compromise|Privileged Account Compromise|Widespread Malware|Major Service / Security Outage)",
            message = "Select a supported incident category.")
    private String category;

    @NotBlank
    @Size(max = 255)
    private String affectedSystem;

    @Size(max = 255)
    private String impactedUserOrDepartment;

    @NotNull
    private Severity severity;

    @NotNull
    private Priority priority;
}
