package com.pareidolia.incidentmanagement.dto;

/** Minimal directory result; id is the internal app_users primary key. */
public record ActiveEmployeeEmailResponse(Long id, String name, String email) { }
