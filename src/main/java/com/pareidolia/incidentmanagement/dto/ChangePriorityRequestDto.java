package com.pareidolia.incidentmanagement.dto;

import com.pareidolia.incidentmanagement.enums.Priority;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class ChangePriorityRequestDto {

    @NotNull
    private Priority priority;

    @NotBlank
    @Size(max = 150)
    private String changedBy;

    @Size(max = 65535)
    private String remarks;
}
