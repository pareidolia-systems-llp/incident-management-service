package com.pareidolia.incidentmanagement.notification;

/** An audited case VIEW grant became active. */
public record DepartmentHeadViewGranted(String incidentNumber, long recipientId) { }
