package com.pareidolia.incidentmanagement.dto;

import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class UpdateInvestigationRequestDto {

    @Size(max = 65535)
    private String investigationDetails;

    @Size(max = 65535)
    private String rootCause;

    @Size(max = 65535)
    private String actionsTaken;

    @Size(max = 65535)
    private String containmentAction;

    @Size(max = 65535)
    private String correctiveAction;

    @Size(max = 65535)
    private String remarks;
}
