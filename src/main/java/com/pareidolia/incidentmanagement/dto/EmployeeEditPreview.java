package com.pareidolia.incidentmanagement.dto;

public record EmployeeEditPreview(EmployeeResponse current, UpdateEmployeeRequest proposed, boolean duplicateName) {}
