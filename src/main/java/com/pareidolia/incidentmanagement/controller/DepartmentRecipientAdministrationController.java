package com.pareidolia.incidentmanagement.controller;

import com.pareidolia.incidentmanagement.service.DepartmentRecipientAdministrationService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;
import java.util.List;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin/department-mail-recipients")
@ConditionalOnProperty(name = "app.notifications.email.recipient-administration.enabled", havingValue = "true")
public class DepartmentRecipientAdministrationController {
    public record Add(@NotNull @Positive Long departmentId, @NotBlank @Email @Size(max = 254) String email,
                      @NotBlank @Size(max = 500) String reason) { }
    public record Change(@NotBlank @Email @Size(max = 254) String email, @NotNull Boolean active,
                         @NotNull @PositiveOrZero Long expectedVersion, @NotBlank @Size(max = 500) String reason) { }
    public record Created(UUID id) { }

    private final DepartmentRecipientAdministrationService service;

    public DepartmentRecipientAdministrationController(DepartmentRecipientAdministrationService service) {
        this.service = service;
    }

    @GetMapping
    public DepartmentRecipientAdministrationService.Directory list() {
        return service.list();
    }

    @GetMapping("/{id}/history")
    public List<DepartmentRecipientAdministrationService.Audit> history(@PathVariable UUID id) {
        return service.history(id);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Created add(@Valid @RequestBody Add request) {
        return new Created(service.add(request.departmentId(), request.email(), request.reason()));
    }

    @PutMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void update(@PathVariable UUID id, @Valid @RequestBody Change request) {
        service.update(id, request.email(), request.active(), request.expectedVersion(), request.reason());
    }
}
