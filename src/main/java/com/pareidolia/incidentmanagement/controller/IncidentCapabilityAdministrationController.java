package com.pareidolia.incidentmanagement.controller;

import com.pareidolia.incidentmanagement.service.IncidentCapabilityAdministrationService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin/incident-security/capabilities")
@ConditionalOnProperty(name={"app.incident-security-admin.enabled","app.incident-access.enabled"},havingValue="true")
public class IncidentCapabilityAdministrationController {
    public record Change(@NotNull Boolean active,@NotNull @PositiveOrZero Long expectedVersion,@NotBlank @Size(max=500) String reason) { }
    public record Result(long version) { }
    private final IncidentCapabilityAdministrationService service;
    public IncidentCapabilityAdministrationController(IncidentCapabilityAdministrationService service){this.service=service;}
    @GetMapping public java.util.List<IncidentCapabilityAdministrationService.Capability> list(){return service.list();}
    @GetMapping("/employees") public java.util.List<IncidentCapabilityAdministrationService.Target> search(@RequestParam String search){return service.search(search);}
    @GetMapping("/{userId}/{capability}/history") public java.util.List<IncidentCapabilityAdministrationService.Audit> history(@PathVariable Long userId,@PathVariable String capability){return service.history(userId,capability);}
    @PutMapping("/{userId}/{capability}") public Result change(@PathVariable Long userId,@PathVariable String capability,@Valid @RequestBody Change request){return new Result(service.change(userId,capability,request.active(),request.expectedVersion(),request.reason()));}
}
