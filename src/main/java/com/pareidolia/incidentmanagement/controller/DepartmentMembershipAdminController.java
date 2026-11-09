package com.pareidolia.incidentmanagement.controller;

import com.pareidolia.incidentmanagement.service.DepartmentMembershipAdminService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;
import java.util.List;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/department-memberships")
@ConditionalOnProperty(name = "app.department-membership-admin.enabled", havingValue = "true")
public class DepartmentMembershipAdminController {
    public record Change(@NotNull Boolean active, @NotNull @PositiveOrZero Long expectedVersion,
                         @NotBlank @Size(max = 500) String reason) { }
    public record Result(long version) { }

    private final DepartmentMembershipAdminService memberships;

    public DepartmentMembershipAdminController(DepartmentMembershipAdminService memberships) {
        this.memberships = memberships;
    }

    @GetMapping("/{departmentId}")
    public List<DepartmentMembershipAdminService.Membership> list(@PathVariable Long departmentId) {
        return memberships.list(departmentId);
    }

    @GetMapping("/{departmentId}/{userId}/history")
    public List<DepartmentMembershipAdminService.Audit> history(@PathVariable Long departmentId, @PathVariable Long userId) {
        return memberships.history(departmentId, userId);
    }

    @PutMapping("/{departmentId}/{userId}")
    public Result change(@PathVariable Long departmentId, @PathVariable Long userId, @Valid @RequestBody Change request) {
        return new Result(memberships.change(departmentId, userId, request.active(), request.expectedVersion(), request.reason()));
    }
}
