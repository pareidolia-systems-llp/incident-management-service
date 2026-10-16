package com.pareidolia.incidentmanagement.controller;

import com.pareidolia.incidentmanagement.service.IncidentReportService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.format.annotation.DateTimeFormat;
import java.time.LocalDate;
import java.time.LocalTime;

@RestController
@RequestMapping("/api/reports/incidents")
@RequiredArgsConstructor
public class IncidentReportController {
    private final IncidentReportService service;

    @GetMapping("/monthly")
    public ResponseEntity<byte[]> monthly(
            @RequestParam(required = false) Integer year,
            @RequestParam(required = false) Integer month,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate fromDate,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.TIME) LocalTime fromTime,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate toDate,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.TIME) LocalTime toTime) {
        byte[] data = service.report(year, month, fromDate, fromTime, toDate, toTime);
        String filename = fromDate == null ? "incident-report-%04d-%02d.xlsx".formatted(year, month)
                : "incident-report-%s-to-%s.xlsx".formatted(fromDate, toDate);
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment()
                        .filename(filename).build().toString())
                .body(data);
    }
}
