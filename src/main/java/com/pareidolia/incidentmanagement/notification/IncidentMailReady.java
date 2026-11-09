package com.pareidolia.incidentmanagement.notification;

/** The first trusted classification makes a case eligible for a dispatch-time check. */
public record IncidentMailReady(String incidentNumber) { }
