package com.pareidolia.incidentmanagement.dto;
public record EmployeeResponse(Long id, String employeeId, String employeeName, String officialEmail, boolean active,
                               boolean googleLoginRecorded, Long version, java.time.LocalDateTime lastLoginAt) {}
