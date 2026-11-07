package com.pareidolia.incidentmanagement.dto;
import jakarta.validation.constraints.*;
import com.pareidolia.incidentmanagement.service.AppUserService;

public record CreateEmployeeRequest(
        @NotBlank @Size(max = 64) String employeeId,
        @NotBlank @Size(max = 255) String employeeName,
        @NotBlank @Email @Size(max = 255) String officialEmail) {
    @com.fasterxml.jackson.annotation.JsonAnySetter
    public void rejectAdditionalField(String name,Object value) { throw new IllegalArgumentException("Unsupported employee field."); }
    public CreateEmployeeRequest {
        employeeName = employeeName == null ? null : employeeName.trim();
        officialEmail = AppUserService.normalizeEmail(officialEmail);
    }
}
