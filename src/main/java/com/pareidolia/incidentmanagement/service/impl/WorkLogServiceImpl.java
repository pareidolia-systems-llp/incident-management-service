package com.pareidolia.incidentmanagement.service.impl;

import com.pareidolia.incidentmanagement.dto.*;
import com.pareidolia.incidentmanagement.entity.*;
import com.pareidolia.incidentmanagement.enums.AppUserRole;
import com.pareidolia.incidentmanagement.exception.InvalidRequestException;
import com.pareidolia.incidentmanagement.repository.WorkLogRepository;
import com.pareidolia.incidentmanagement.service.*;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;

@Service
@RequiredArgsConstructor
public class WorkLogServiceImpl implements WorkLogService {
    private final AppUserService users;
    private final WorkLogRepository entries;

    private AppUser operationalUser() {
        AppUser actor = users.getAuthenticatedUser();
        if (!Boolean.TRUE.equals(actor.getActive()) || actor.getId() == null
                || (actor.getRole() != AppUserRole.IT_HANDLER && actor.getRole() != AppUserRole.ADMIN)) {
            throw new AccessDeniedException("Access denied.");
        }
        return actor;
    }

    @Override
    @Transactional(readOnly = true)
    public List<WorkLogResponseDto> listOwnEntries() {
        return entries.findByOwnerIdOrderByWorkedAtDescIdDesc(operationalUser().getId()).stream()
                .map(this::response).toList();
    }

    @Override
    @Transactional
    public WorkLogResponseDto createOwnEntry(CreateWorkLogRequestDto request) {
        AppUser actor = operationalUser();
        if (request.getWorkedAt().getYear() < 1900 || request.getWorkedAt().getYear() > 9998) {
            throw new InvalidRequestException("Select a work date from 1900 to 9998.");
        }
        WorkLogEntry entry = new WorkLogEntry();
        entry.setOwner(actor);
        entry.setWorkedAt(request.getWorkedAt());
        entry.setCategory(request.getCategory());
        entry.setSummary(request.getSummary().trim());
        entry.setDetails(request.getDetails() == null || request.getDetails().isBlank() ? null : request.getDetails().trim());
        entry.setDurationMinutes(request.getDurationMinutes());
        return response(entries.saveAndFlush(entry));
    }

    private WorkLogResponseDto response(WorkLogEntry entry) {
        return new WorkLogResponseDto(entry.getId(), entry.getWorkedAt(), entry.getCategory(),
                entry.getSummary(), entry.getDetails(), entry.getDurationMinutes(), entry.getCreatedAt());
    }
}
