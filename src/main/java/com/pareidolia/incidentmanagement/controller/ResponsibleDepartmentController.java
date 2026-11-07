package com.pareidolia.incidentmanagement.controller;

import com.pareidolia.incidentmanagement.repository.IncidentRepository;
import com.pareidolia.incidentmanagement.service.AppUserService;
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

    public record Department(Long id, String displayName) { }

    @GetMapping
    public List<Department> list() {
        users.getAuthenticatedUser();
        return incidents.findActiveResponsibleDepartments().stream()
                .map(row -> new Department(row.getId(), row.getDisplayName()))
                .toList();
    }
}
