package com.pareidolia.incidentmanagement.dto;

import com.pareidolia.incidentmanagement.enums.IssueType;
import com.pareidolia.incidentmanagement.enums.Priority;
import com.pareidolia.incidentmanagement.enums.Severity;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
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

    @NotBlank
    @Size(max = 255)
    private String title;

    @NotBlank
    @Size(max = 65535)
    private String description;

    @NotNull
    private IssueType issueType;

    @Size(max = 100)
    private String category;

    @Size(max = 255)
    private String affectedSystem;

    @Size(max = 255)
    private String impactedUserOrDepartment;

    @NotNull
    private Severity severity;

    @NotNull
    private Priority priority;
}
