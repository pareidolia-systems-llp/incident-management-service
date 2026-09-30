package com.pareidolia.incidentmanagement.dto;

import com.pareidolia.incidentmanagement.enums.Severity;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class ChangeSeverityRequestDto {

    @NotNull
    private Severity severity;

    @Size(max = 65535)
    private String remarks;
}
