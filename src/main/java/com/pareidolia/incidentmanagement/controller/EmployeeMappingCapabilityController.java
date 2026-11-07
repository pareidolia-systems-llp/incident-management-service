package com.pareidolia.incidentmanagement.controller;

import com.pareidolia.incidentmanagement.service.EmployeeMappingCapabilityService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.*;

/** The service requires a separately bootstrapped capability administrator. */
@RestController
@RequestMapping("/api/admin/mapping-capabilities")
@ConditionalOnProperty(name="app.employee-capability-management.enabled",havingValue="true")
public class EmployeeMappingCapabilityController {
    public record Change(@NotNull Boolean active, @NotBlank @Size(max=500) String reason) { }
    public record Result(boolean changed) { }
    private final EmployeeMappingCapabilityService service;
    public EmployeeMappingCapabilityController(EmployeeMappingCapabilityService service) { this.service=service; }
    @PutMapping("/{userId}")
    public Result change(@PathVariable Long userId, @Valid @RequestBody Change change) {
        return new Result(service.setMappingAdmin(userId,change.active(),change.reason()));
    }
}
