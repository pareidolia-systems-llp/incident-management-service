package com.pareidolia.incidentmanagement.controller;

import com.pareidolia.incidentmanagement.repository.IncidentRepository;
import com.pareidolia.incidentmanagement.service.AppUserService;
import com.pareidolia.incidentmanagement.service.IncidentService;
import com.pareidolia.incidentmanagement.service.ResponsibleDepartments;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/incidents/responsible-departments")
@RequiredArgsConstructor
public class ResponsibleDepartmentController {

    private final IncidentRepository incidents;
    private final AppUserService users;
    private final IncidentService incidentService;

    public record Department(Long id, String displayName) { }

    @GetMapping
    public List<Department> list() {
        users.getAuthenticatedUser();
        if (!incidentService.departmentScopedIntakeAvailable()) return List.of();
        return incidents.findActiveResponsibleDepartments().stream()
                .filter(row -> ResponsibleDepartments.includes(row.getDisplayName()))
                .map(row -> new Department(row.getId(), ResponsibleDepartments.displayName(row.getDisplayName())))
                .toList();
    }
}
