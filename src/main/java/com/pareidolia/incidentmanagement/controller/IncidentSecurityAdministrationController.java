package com.pareidolia.incidentmanagement.controller;

import com.pareidolia.incidentmanagement.service.IncidentSecurityAdministrationService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin/incident-security")
@ConditionalOnProperty(name={"app.incident-security-admin.enabled","app.incident-access.enabled"},havingValue="true")
public class IncidentSecurityAdministrationController {
    public record ClassificationChange(@NotBlank String classification,@NotNull @PositiveOrZero Long expectedVersion,@NotBlank @Size(max=500) String reason) { }
    public record GrantChange(@NotNull Boolean active,@NotNull @PositiveOrZero Long expectedVersion,@NotBlank @Size(max=500) String reason) { }
    public record Version(long version) { }
    private final IncidentSecurityAdministrationService service;
    public IncidentSecurityAdministrationController(IncidentSecurityAdministrationService service){this.service=service;}
    @GetMapping("/employees") public java.util.List<IncidentSecurityAdministrationService.CaseTarget> searchTargets(@RequestParam String search){return service.searchTargets(search);}
    @GetMapping("/triage") public java.util.List<IncidentSecurityAdministrationService.Triage> triage(){return service.triage();}
    @GetMapping("/{incidentId}/classification") public IncidentSecurityAdministrationService.Triage classification(@PathVariable Long incidentId){return service.classification(incidentId);}
    @PutMapping("/{incidentId}/classification") public IncidentSecurityAdministrationService.ClassificationResult classify(@PathVariable Long incidentId,@Valid @RequestBody ClassificationChange request){return service.classify(incidentId,request.classification(),request.expectedVersion(),request.reason());}
    @GetMapping("/{incidentId}/classification/history") public java.util.List<IncidentSecurityAdministrationService.ClassificationHistory> classificationHistory(@PathVariable Long incidentId){return service.classificationHistory(incidentId);}
    @GetMapping("/{incidentId}/grants") public java.util.List<IncidentSecurityAdministrationService.CaseGrant> grants(@PathVariable Long incidentId){return service.grants(incidentId);}
    @GetMapping("/{incidentId}/grants/{userId}/{permission}/history") public java.util.List<IncidentSecurityAdministrationService.GrantHistory> grantHistory(@PathVariable Long incidentId,@PathVariable Long userId,@PathVariable String permission){return service.grantHistory(incidentId,userId,permission);}
    @PutMapping("/{incidentId}/grants/{userId}/{permission}") public Version grant(@PathVariable Long incidentId,@PathVariable Long userId,@PathVariable String permission,@Valid @RequestBody GrantChange request){return new Version(service.setGrant(incidentId,userId,permission,request.active(),request.expectedVersion(),request.reason()));}
}
