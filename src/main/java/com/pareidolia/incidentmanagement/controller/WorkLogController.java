package com.pareidolia.incidentmanagement.controller;

import com.pareidolia.incidentmanagement.dto.*;
import com.pareidolia.incidentmanagement.exception.InvalidRequestException;
import com.pareidolia.incidentmanagement.service.WorkLogService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/work-logs")
@RequiredArgsConstructor
public class WorkLogController {
    private final WorkLogService service;

    @GetMapping
    public ResponseEntity<List<WorkLogResponseDto>> list(@RequestParam Map<String, String> parameters) {
        if (!parameters.isEmpty()) throw new InvalidRequestException("Work logs do not accept owner filters or query parameters.");
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(service.listOwnEntries());
    }

    @PostMapping
    public ResponseEntity<WorkLogResponseDto> create(@Valid @RequestBody CreateWorkLogRequestDto request) {
        return ResponseEntity.status(HttpStatus.CREATED).cacheControl(CacheControl.noStore())
                .body(service.createOwnEntry(request));
    }
}
