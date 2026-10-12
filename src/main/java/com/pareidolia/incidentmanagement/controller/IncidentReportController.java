package com.pareidolia.incidentmanagement.controller;

import com.pareidolia.incidentmanagement.service.IncidentReportService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/reports/incidents")
@RequiredArgsConstructor
public class IncidentReportController {
    private final IncidentReportService service;

    @GetMapping("/monthly")
    public ResponseEntity<byte[]> monthly(@RequestParam int year, @RequestParam int month) {
        byte[] data = service.monthly(year, month);
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment()
                        .filename("incident-report-%04d-%02d.xlsx".formatted(year, month)).build().toString())
                .body(data);
    }
}
