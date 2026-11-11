package com.pareidolia.incidentmanagement;

import com.pareidolia.incidentmanagement.controller.EmployeeController;
import com.pareidolia.incidentmanagement.controller.EmployeeDirectoryAdminController;
import com.pareidolia.incidentmanagement.dto.EmployeePageResponse;
import com.pareidolia.incidentmanagement.entity.AppUser;
import com.pareidolia.incidentmanagement.exception.GlobalExceptionHandler;
import com.pareidolia.incidentmanagement.repository.AppUserRepository;
import com.pareidolia.incidentmanagement.security.EmployeeManagementAccess;
import com.pareidolia.incidentmanagement.service.AppUserService;
import com.pareidolia.incidentmanagement.service.EmployeeDirectoryService;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class ActiveEmployeeEmailSearchHttpTests {
    private static final String EMPLOYEES = "/api/admin/employees";
    private static final String SEARCH = EMPLOYEES + "/active-email-search";

    @Test
    void disabledSearchFallsThroughToNumericIdWhileDirectoryListReturnsAPage() throws Exception {
        var directory = mock(EmployeeDirectoryService.class);
        when(directory.list("example", 0, 20)).thenReturn(new EmployeePageResponse(List.of(), 0, 20, 0, 0));
        var mvc = MockMvcBuilders.standaloneSetup(new EmployeeController(directory)).build();

        mvc.perform(get(EMPLOYEES).param("search", "example"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.content").isArray());
        mvc.perform(get(SEARCH).param("search", "example")).andExpect(status().isBadRequest());
        verify(directory, never()).view(anyLong());
    }

    @Test
    void dedicatedSearchReturnsActiveAccountProjectionsAndEnforcesExistingChecks() throws Exception {
        var users = mock(AppUserService.class);
        var repository = mock(AppUserRepository.class);
        var access = mock(EmployeeManagementAccess.class);
        var actor = new AppUser();
        var match = new AppUser();
        match.setId(7L);
        match.setDisplayName("Example Person");
        match.setEmail("person@example.test");
        when(users.getAuthenticatedUser()).thenReturn(actor);
        when(access.canManage(actor)).thenReturn(true);
        var page = PageRequest.of(0, 10, Sort.by("email", "id"));
        when(repository.findByActiveTrueAndEmailContainingIgnoreCase("example", page))
                .thenReturn(new PageImpl<>(List.of(match)));
        var mvc = MockMvcBuilders.standaloneSetup(new EmployeeController(mock(EmployeeDirectoryService.class)),
                new EmployeeDirectoryAdminController(users, repository, access))
                .setControllerAdvice(new GlobalExceptionHandler()).build();

        mvc.perform(get(SEARCH).param("search", " example ")).andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$[0].id").value(7))
                .andExpect(jsonPath("$[0].name").value("Example Person"))
                .andExpect(jsonPath("$[0].email").value("person@example.test"))
                .andExpect(jsonPath("$[0].role").doesNotExist());
        mvc.perform(get(SEARCH).param("search", " x ")).andExpect(status().isBadRequest());
        when(access.canManage(actor)).thenReturn(false);
        mvc.perform(get(SEARCH).param("search", "example")).andExpect(status().isForbidden());
        verify(repository).findByActiveTrueAndEmailContainingIgnoreCase("example", page);
        verifyNoMoreInteractions(repository);
    }
}
