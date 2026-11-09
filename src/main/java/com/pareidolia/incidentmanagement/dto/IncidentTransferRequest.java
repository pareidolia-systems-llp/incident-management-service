package com.pareidolia.incidentmanagement.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;

/** The operator-supplied handoff reference is format-checked, not independently verified. */
public record IncidentTransferRequest(
        @NotNull @Positive Long expectedSourceDepartmentId,
        @NotNull @Positive Long destinationDepartmentId,
        @NotNull @Positive Long destinationHandlerUserId,
        @NotNull @PositiveOrZero Long expectedVersion,
        @NotNull @PositiveOrZero Long expectedClassificationVersion,
        @NotBlank @Size(max = 500) String reason,
        @NotBlank @Pattern(regexp = APPROVAL_REFERENCE_PATTERN) String handoffApprovalReference) {
    public static final String APPROVAL_REFERENCE_PATTERN = "[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}";
}
