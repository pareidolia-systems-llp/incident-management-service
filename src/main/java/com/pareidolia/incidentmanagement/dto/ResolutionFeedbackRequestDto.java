package com.pareidolia.incidentmanagement.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class ResolutionFeedbackRequestDto {

    @NotBlank
    @Size(max = 8000)
    private String feedback;

    @Size(max = 500)
    private String evidenceReference;
}
