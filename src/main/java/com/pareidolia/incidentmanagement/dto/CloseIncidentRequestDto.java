package com.pareidolia.incidentmanagement.dto;

import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class CloseIncidentRequestDto {

    @Size(max = 65535)
    private String remarks;
}
