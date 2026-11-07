package com.pareidolia.incidentmanagement.dto;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UpdateEmployeeRequest(
        @Size(max = 64) @jakarta.validation.constraints.Pattern(regexp = "(?s).*\\S.*") String employeeId,
        @NotBlank @Size(max = 255) String employeeName,
        @NotBlank @Size(max = 500) String reason,
        @jakarta.validation.constraints.NotNull @jakarta.validation.constraints.PositiveOrZero Long expectedVersion) {
    public UpdateEmployeeRequest {
        employeeName = employeeName == null ? null : employeeName.trim();
        reason = reason == null ? null : reason.strip();
    }
    @JsonAnySetter
    public void rejectAdditionalField(String name, Object value) {
        throw new IllegalArgumentException("Only Employee ID and name can be updated.");
    }
}
