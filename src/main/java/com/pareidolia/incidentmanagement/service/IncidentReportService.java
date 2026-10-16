package com.pareidolia.incidentmanagement.service;

public interface IncidentReportService {
    byte[] monthly(int year, int month);

    byte[] report(Integer year, Integer month, java.time.LocalDate fromDate, java.time.LocalTime fromTime,
                  java.time.LocalDate toDate, java.time.LocalTime toTime);
}
