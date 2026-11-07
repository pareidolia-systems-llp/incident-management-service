package com.pareidolia.incidentmanagement;

import com.pareidolia.incidentmanagement.controller.EmployeeDirectoryAdminController;
import com.pareidolia.incidentmanagement.controller.EmployeeMappingCapabilityController;
import com.pareidolia.incidentmanagement.entity.AppUser;
import com.pareidolia.incidentmanagement.repository.AppUserRepository;
import com.pareidolia.incidentmanagement.security.EmployeeManagementAccess;
import com.pareidolia.incidentmanagement.service.AppUserService;
import com.pareidolia.incidentmanagement.service.EmployeeMappingCapabilityService;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.server.ResponseStatusException;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class AdministrativeEndpointsTests {
    @Test void adminDirectoryRejectsUnauthorizedAndShortSearches() {
        var users=mock(AppUserService.class); var repository=mock(AppUserRepository.class);
        var access=mock(EmployeeManagementAccess.class); var actor=new AppUser();
        when(users.getAuthenticatedUser()).thenReturn(actor);
        var controller=new EmployeeDirectoryAdminController(users,repository,access);
        assertThatThrownBy(() -> controller.search("ab")).isInstanceOf(AccessDeniedException.class);
        when(access.canManage(actor)).thenReturn(true);
        assertThatThrownBy(() -> controller.search("a")).isInstanceOf(ResponseStatusException.class);
        verifyNoInteractions(repository);
    }
    @Test void capabilityEndpointUsesIndependentlyAuthorizedService() {
        var service=mock(EmployeeMappingCapabilityService.class);
        when(service.setMappingAdmin(42L,true,"Reason")).thenReturn(true);
        var controller=new EmployeeMappingCapabilityController(service);
        assertThat(controller.change(42L,new EmployeeMappingCapabilityController.Change(true,"Reason")).changed()).isTrue();
        verify(service).setMappingAdmin(42L,true,"Reason");
    }
}
