package com.pareidolia.incidentmanagement.controller;

import com.pareidolia.incidentmanagement.dto.*;
import com.pareidolia.incidentmanagement.service.EmployeeDirectoryService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin/employees")
@ConditionalOnProperty(name="app.employee-management.enabled",havingValue="true")
public class EmployeeController {
    public record StatusChange(@NotNull Boolean active,@NotNull @PositiveOrZero Long expectedVersion,@NotBlank @Size(max=500) String reason) { }
    private final EmployeeDirectoryService employees;
    public EmployeeController(EmployeeDirectoryService employees){this.employees=employees;}
    @GetMapping public EmployeePageResponse list(@RequestParam(defaultValue="") String search,@RequestParam(defaultValue="0") int page,@RequestParam(defaultValue="20") int size){return employees.list(search,page,size);}
    @GetMapping("/{id}/history") public java.util.List<EmployeeDirectoryService.Audit> history(@PathVariable Long id){return employees.history(id);}
    @GetMapping("/{id}") public EmployeeResponse view(@PathVariable Long id){return employees.view(id);}
    @PostMapping @ResponseStatus(HttpStatus.CREATED) public EmployeeResponse create(@Valid @RequestBody CreateEmployeeRequest request){return employees.create(request);}
    @PostMapping("/{id}/preview") public EmployeeEditPreview preview(@PathVariable Long id,@Valid @RequestBody UpdateEmployeeRequest request){return employees.preview(id,request);}
    @PutMapping("/{id}") public EmployeeResponse update(@PathVariable Long id,@Valid @RequestBody UpdateEmployeeRequest request){return employees.update(id,request);}
    @PutMapping("/{id}/status") public EmployeeResponse status(@PathVariable Long id,@Valid @RequestBody StatusChange request){return employees.status(id,request.active(),request.expectedVersion(),request.reason());}
}
