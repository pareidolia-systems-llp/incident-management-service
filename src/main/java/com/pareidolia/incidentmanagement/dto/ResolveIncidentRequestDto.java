package com.pareidolia.incidentmanagement.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class ResolveIncidentRequestDto {

    @NotBlank
    @Size(max = 65535)
    private String resolutionDetails;

    @NotBlank
    @Size(max = 150)
    private String changedBy;

    @Size(max = 65535)
    private String remarks;
}
