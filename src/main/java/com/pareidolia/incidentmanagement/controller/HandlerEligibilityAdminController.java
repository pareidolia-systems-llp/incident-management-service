package com.pareidolia.incidentmanagement.controller;

import com.pareidolia.incidentmanagement.service.HandlerEligibilityAdminService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin/handler-eligibility")
@ConditionalOnProperty(name="app.handler-eligibility-admin.enabled",havingValue="true")
public class HandlerEligibilityAdminController {
    public record Change(@NotNull Boolean active, Long expectedVersion, @NotBlank @Size(max=500) String reason) { }
    public record Result(long version) { }
    private final HandlerEligibilityAdminService service;
    public HandlerEligibilityAdminController(HandlerEligibilityAdminService service){this.service=service;}
    @GetMapping
    public java.util.List<HandlerEligibilityAdminService.Grant> list(){return service.list();}
    @GetMapping("/{userId}/history")
    public java.util.List<HandlerEligibilityAdminService.Audit> history(@PathVariable Long userId){return service.history(userId);}
    @PutMapping("/{userId}")
    public Result change(@PathVariable Long userId,@Valid @RequestBody Change request){
        return new Result(service.change(userId,request.active(),request.expectedVersion(),request.reason()));
    }
}
