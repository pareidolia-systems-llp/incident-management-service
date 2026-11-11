package com.pareidolia.incidentmanagement.service.impl;

import com.pareidolia.incidentmanagement.dto.*;
import com.pareidolia.incidentmanagement.entity.*;
import com.pareidolia.incidentmanagement.enums.*;
import com.pareidolia.incidentmanagement.exception.*;
import com.pareidolia.incidentmanagement.repository.*;
import com.pareidolia.incidentmanagement.service.*;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import javax.imageio.ImageIO;
import javax.imageio.stream.MemoryCacheImageInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

@Service
@RequiredArgsConstructor
public class IncidentAttachmentServiceImpl implements IncidentAttachmentService {
    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private com.pareidolia.incidentmanagement.security.IncidentSecurityGate securityGate;
    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private com.pareidolia.incidentmanagement.security.IncidentReadSnapshot readSnapshot;
    @org.springframework.beans.factory.annotation.Value("${app.incident-access.enabled:false}") private boolean securityGateEnabled;
    private void securityWrite(){
        if(securityGateEnabled){if(securityGate==null)throw new IllegalStateException("Security gate unavailable.");securityGate.write();}
    }
    private <T> T secureRead(java.util.function.Supplier<T> work){
        if(readSnapshot==null)throw new IllegalStateException("Security snapshot unavailable.");
        return incidentAccessEnabled ? readSnapshot.read(work) : readSnapshot.readForRollback(work);
    }
    private static final int MAX_BYTES = 5 * 1024 * 1024;
    private static final long MAX_PIXELS = 20_000_000;
    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private com.pareidolia.incidentmanagement.security.IncidentAccessPolicy accessPolicy;
    @org.springframework.beans.factory.annotation.Value("${app.incident-access.enabled:false}") private boolean incidentAccessEnabled;
    private final IncidentService incidentService;
    private final AppUserService users;
    private final IncidentRepository incidents;
    private final IncidentAttachmentRepository attachments;
    private final IncidentHistoryRepository history;

    @Override
    public List<IncidentAttachmentResponseDto> list(Long incidentId) {
        return secureRead(() -> {
        if (incidentAccessEnabled) incidentService.checkAttachmentRead(incidentId, false);
        else incidentService.getIncident(incidentId);
        return attachments.findMetadataByIncidentId(incidentId);

        });
    }

    @Override
    public AttachmentContentDto content(Long incidentId, Long attachmentId) {
        return secureRead(() -> {
        if (incidentAccessEnabled) incidentService.checkAttachmentRead(incidentId, true);
        else incidentService.getIncident(incidentId);
        var attachment = attachments.findByIdAndIncidentId(attachmentId, incidentId)
                .orElseThrow(() -> new IncidentNotFoundException("Attachment not found."));
        return new AttachmentContentDto(attachment.getOriginalFilename(), attachment.getContentType(), attachment.getFileData());

        });
    }

    @Override
    @Transactional
    public List<IncidentAttachmentResponseDto> upload(Long incidentId, List<MultipartFile> files) {
        securityWrite();
        if (!incidentAccessEnabled) incidentService.getIncident(incidentId);
        AppUser actor = users.getAuthenticatedUser();
        if (actor.getRole() != AppUserRole.REPORTER && actor.getRole() != AppUserRole.IT_HANDLER
                && actor.getRole() != AppUserRole.ADMIN) throw new AccessDeniedException("Access denied.");
        Incident incident = incidentAccessEnabled
                ? incidents.findById(incidentId).orElseThrow(() -> new IncidentNotFoundException("Incident not found."))
                : incidents.getReferenceById(incidentId);
        if (!incidentAccessEnabled && com.pareidolia.incidentmanagement.security.IncidentConfidentiality
                .persistedRestrictions(List.of(incident), incidents).contains(incidentId)) {
            throw new IncidentNotFoundException("Incident not found.");
        }
        if (incidentAccessEnabled) {
            boolean reporter = actor.getRole() == AppUserRole.REPORTER;
            var permission = reporter
                    ? com.pareidolia.incidentmanagement.security.IncidentAccessPolicy.Permission.VIEW
                    : com.pareidolia.incidentmanagement.security.IncidentAccessPolicy.Permission.MODIFY;
            if (accessPolicy == null || !accessPolicy.canForMutation(actor, incident, permission)
                    || (reporter && (actor.getRole() != AppUserRole.REPORTER
                        || !com.pareidolia.incidentmanagement.security.IncidentConfidentiality.isReporter(actor, incident)))) {
                throw new IncidentNotFoundException("Incident not found.");
            }
        }
        if (incidentAccessEnabled && actor.getRole() != AppUserRole.REPORTER && actor.getRole() != AppUserRole.IT_HANDLER && actor.getRole() != AppUserRole.ADMIN) throw new IncidentNotFoundException("Incident not found.");
        if (files == null || files.isEmpty() || files.size() > 5) {
            throw new InvalidRequestException("Select between 1 and 5 images per upload.");
        }
        // Validate the entire batch before any write. Attachment and audit writes commit atomically.
        List<IncidentAttachment> validated = files.stream().map(this::validate).toList();

        List<IncidentAttachmentResponseDto> result = new ArrayList<>();
        for (IncidentAttachment attachment : validated) {
            attachment.setIncident(incident);
            attachment.setUploadedBy(actor.getEmail());
            attachment.setUploadedAt(LocalDateTime.now());
            attachments.save(attachment);
            IncidentHistory event = new IncidentHistory();
            event.setIncident(incident);
            event.setActionType(HistoryActionType.ATTACHMENT_ADDED);
            event.setChangedBy(actor.getEmail());
            event.setNewValue(attachment.getId().toString());
            event.setRemarks("Screenshot added: " + attachment.getOriginalFilename());
            history.save(event);
            result.add(new IncidentAttachmentResponseDto(attachment.getId(), attachment.getOriginalFilename(),
                    attachment.getContentType(), attachment.getFileSize(), attachment.getUploadedBy(), attachment.getUploadedAt()));
        }
        return result;
    }

    private IncidentAttachment validate(MultipartFile file) {
        if (file == null || file.isEmpty() || file.getSize() > MAX_BYTES) {
            throw new InvalidRequestException("Each screenshot must contain an image and be no larger than 5 MB.");
        }
        try {
            byte[] data = file.getBytes();
            String type;
            try (var input = new MemoryCacheImageInputStream(new ByteArrayInputStream(data))) {
                var readers = ImageIO.getImageReaders(input);
                if (!readers.hasNext()) throw new InvalidRequestException("Only valid PNG and JPEG images are allowed.");
                var reader = readers.next();
                try {
                    reader.setInput(input, true, true);
                    String format = reader.getFormatName().toLowerCase(Locale.ROOT);
                    type = switch (format) {
                        case "png" -> "image/png";
                        case "jpeg", "jpg" -> "image/jpeg";
                        default -> throw new InvalidRequestException("Only PNG and JPEG images are allowed.");
                    };
                    int width = reader.getWidth(0), height = reader.getHeight(0);
                    if (width <= 0 || height <= 0 || (long) width * height > MAX_PIXELS) {
                        throw new InvalidRequestException("Screenshot dimensions must not exceed 20 million pixels.");
                    }
                    // Decode to detect damaged image contents; bound dimensions before allocating pixels.
                    var decoded = reader.read(0);
                    if (decoded == null) throw new InvalidRequestException("The screenshot could not be decoded.");
                    decoded.flush();
                } finally { reader.dispose(); }
            }
            IncidentAttachment attachment = new IncidentAttachment();
            attachment.setOriginalFilename(safeFilename(file.getOriginalFilename(), type));
            attachment.setContentType(type);
            attachment.setFileData(data);
            attachment.setFileSize(data.length);
            return attachment;
        } catch (IOException | IllegalArgumentException exception) {
            throw new InvalidRequestException("The screenshot is not a readable PNG or JPEG image.");
        }
    }

    private String safeFilename(String original, String type) {
        String name = original == null ? "screenshot" : original.replace('\\', '/');
        name = name.substring(name.lastIndexOf('/') + 1).replaceAll("[^a-zA-Z0-9._ -]", "_");
        int dot = name.lastIndexOf('.');
        if (dot > 0) name = name.substring(0, dot);
        name = name.replaceAll("^[. ]+|[. ]+$", "");
        if (name.isBlank()) name = "screenshot";
        return name.substring(0, Math.min(name.length(), 170)) + (type.equals("image/png") ? ".png" : ".jpg");
    }
}
