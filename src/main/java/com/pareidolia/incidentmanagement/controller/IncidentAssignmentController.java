package com.pareidolia.incidentmanagement.controller;

import com.pareidolia.incidentmanagement.dto.IncidentTransferRequest;
import com.pareidolia.incidentmanagement.service.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/incident-assignment")
@ConditionalOnProperty(name={"app.incident-assignment.enabled","app.incident-access.enabled","app.employee-management.enabled"},havingValue="true")
public class IncidentAssignmentController {
    public record Change(@NotNull @Positive Long handlerUserId,@NotNull @PositiveOrZero Long expectedVersion,@NotNull @PositiveOrZero Long expectedClassificationVersion,@NotBlank @Size(max=500) String reason) { }
    private final IncidentAssignmentService service;
    public IncidentAssignmentController(IncidentAssignmentService service){this.service=service;}
    @GetMapping("/handlers") public java.util.List<EligibleHandlerDirectory.Employee> search(@RequestParam String search,@RequestParam(required=false) Long incidentId){return service.search(search,incidentId);}
    @GetMapping("/triage") public java.util.List<IncidentAssignmentService.QueueItem> triage(){return service.triage();}
    @GetMapping("/triage/{id}") public IncidentAssignmentService.TriageDetail triageDetail(@PathVariable Long id){return service.triageDetail(id);}
    @GetMapping("/{id}") public IncidentAssignmentService.State state(@PathVariable Long id){return service.get(id);}
    @GetMapping("/{id}/history") public java.util.List<IncidentAssignmentService.Audit> history(@PathVariable Long id){return service.history(id);}
    @GetMapping("/{id}/transfer/options")
    public IncidentAssignmentService.TransferOptions transferOptions(@PathVariable Long id) {
        return service.transferOptions(id);
    }
    @GetMapping("/{id}/transfer/handlers")
    public IncidentAssignmentService.TransferHandlers transferHandlers(@PathVariable Long id,
            @RequestParam Long destinationDepartmentId, @RequestParam String search) {
        return service.transferHandlers(id, destinationDepartmentId, search);
    }
    @PostMapping("/{id}/transfer")
    public IncidentAssignmentService.TransferResult transfer(@PathVariable Long id, @Valid @RequestBody IncidentTransferRequest request) {
        return service.transfer(id, request);
    }
    @PostMapping("/{id}") public IncidentAssignmentService.State assign(@PathVariable Long id,@Valid @RequestBody Change request){return service.assign(id,request.handlerUserId(),request.expectedVersion(),request.expectedClassificationVersion(),request.reason());}
}
