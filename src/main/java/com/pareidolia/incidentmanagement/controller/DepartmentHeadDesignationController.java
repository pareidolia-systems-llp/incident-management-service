package com.pareidolia.incidentmanagement.controller;

import com.pareidolia.incidentmanagement.service.DepartmentHeadDesignationService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.List;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin/department-head-designations")
@ConditionalOnProperty(name="app.department-head-designations.enabled",havingValue="true")
public class DepartmentHeadDesignationController {
    public record Change(@NotNull Boolean active,Long expectedVersion,@NotBlank @Size(max=500) String reason) { }
    public record Changed(long version) { }
    private final DepartmentHeadDesignationService service;
    public DepartmentHeadDesignationController(DepartmentHeadDesignationService service) {this.service=service;}
    @GetMapping("/departments")
    public List<DepartmentHeadDesignationService.Department> departments(){return service.departments();}
    @GetMapping
    public List<DepartmentHeadDesignationService.Designation> list(){return service.list();}
    @GetMapping("/{departmentId}/{userId}/history")
    public List<DepartmentHeadDesignationService.AuditEntry> history(@PathVariable Long departmentId,@PathVariable Long userId){
        return service.history(departmentId,userId);
    }
    @PutMapping("/{departmentId}/{userId}")
    public Changed set(@PathVariable Long departmentId,@PathVariable Long userId,@Valid @RequestBody Change request){
        return new Changed(service.set(departmentId,userId,request.active(),request.expectedVersion(),request.reason()));
    }
}
