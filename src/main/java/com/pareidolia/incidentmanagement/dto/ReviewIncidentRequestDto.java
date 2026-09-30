package com.pareidolia.incidentmanagement.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class ReviewIncidentRequestDto {

    @NotBlank
    @Size(max = 65535)
    private String reviewDetails;

    @Size(max = 65535)
    private String lessonsLearned;

    @Size(max = 65535)
    private String preventiveAction;

    @Size(max = 65535)
    private String remarks;
}
