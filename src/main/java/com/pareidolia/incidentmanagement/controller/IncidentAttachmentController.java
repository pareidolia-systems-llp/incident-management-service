package com.pareidolia.incidentmanagement.controller;

import com.pareidolia.incidentmanagement.dto.IncidentAttachmentResponseDto;
import com.pareidolia.incidentmanagement.service.IncidentAttachmentService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.util.List;

@RestController
@RequestMapping("/api/incidents/{incidentId}/attachments")
@RequiredArgsConstructor
public class IncidentAttachmentController {
    private final IncidentAttachmentService service;

    @GetMapping
    public List<IncidentAttachmentResponseDto> list(@PathVariable Long incidentId) {
        return service.list(incidentId);
    }

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<List<IncidentAttachmentResponseDto>> upload(
            @PathVariable Long incidentId, @RequestParam("files") List<MultipartFile> files) {
        return ResponseEntity.status(HttpStatus.CREATED).body(service.upload(incidentId, files));
    }

    @GetMapping("/{attachmentId}")
    public ResponseEntity<byte[]> content(@PathVariable Long incidentId, @PathVariable Long attachmentId) {
        var content = service.content(incidentId, attachmentId);
        return ResponseEntity.ok().contentType(MediaType.parseMediaType(content.contentType()))
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment().filename(content.filename()).build().toString())
                .header("X-Content-Type-Options", "nosniff")
                .body(content.data());
    }
}
