package com.pareidolia.incidentmanagement.controller;

import com.pareidolia.incidentmanagement.dto.ActiveEmployeeEmailResponse;
import com.pareidolia.incidentmanagement.repository.AppUserRepository;
import com.pareidolia.incidentmanagement.security.EmployeeManagementAccess;
import com.pareidolia.incidentmanagement.service.AppUserService;
import java.util.List;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

/** Separate HR/IT admin lookup, never a reporter eligibility endpoint. */
@RestController
@RequestMapping("/api/admin/employees")
@ConditionalOnProperty(name="app.employee-assignment.active-email-search.enabled", havingValue="true")
public class EmployeeDirectoryAdminController {
    private final AppUserService users;
    private final AppUserRepository repository;
    private final EmployeeManagementAccess access;
    public EmployeeDirectoryAdminController(AppUserService users, AppUserRepository repository, EmployeeManagementAccess access) {
        this.users=users; this.repository=repository; this.access=access;
    }
    @GetMapping("/active-email-search")
    public List<ActiveEmployeeEmailResponse> search(@RequestParam String search) {
        if (!access.canManage(users.getAuthenticatedUser())) throw new AccessDeniedException("Access denied.");
        if (search == null || search.trim().length()<2 || search.trim().length()>255)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Enter at least two email characters.");
        return repository.findByActiveTrueAndEmailContainingIgnoreCase(search.trim(),
            PageRequest.of(0,10,Sort.by("email", "id"))).getContent().stream()
            .map(u -> new ActiveEmployeeEmailResponse(u.getId(),u.getDisplayName(),u.getEmail())).toList();
    }
}
