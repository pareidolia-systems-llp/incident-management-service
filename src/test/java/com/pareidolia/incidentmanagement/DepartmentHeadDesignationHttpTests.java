package com.pareidolia.incidentmanagement;

import com.pareidolia.incidentmanagement.controller.DepartmentHeadDesignationController;
import com.pareidolia.incidentmanagement.exception.GlobalExceptionHandler;
import com.pareidolia.incidentmanagement.service.DepartmentHeadDesignationService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class DepartmentHeadDesignationHttpTests {
    @Test void controllerIsNotRegisteredWhenFlagAbsent() {
        new ApplicationContextRunner().withUserConfiguration(DepartmentHeadDesignationController.class)
            .run(context -> assertThat(context).hasNotFailed().doesNotHaveBean(DepartmentHeadDesignationController.class));
    }
    @Test void changeForwardsAccountIdsReasonAndVersion() throws Exception {
        var service=mock(DepartmentHeadDesignationService.class);
        when(service.set(1L,8L,true,null,"Approved")).thenReturn(0L);
        var mvc=MockMvcBuilders.standaloneSetup(new DepartmentHeadDesignationController(service)).setControllerAdvice(new GlobalExceptionHandler()).build();
        mvc.perform(put("/api/admin/department-head-designations/1/8").contentType(MediaType.APPLICATION_JSON)
            .content("{\"active\":true,\"expectedVersion\":null,\"reason\":\"Approved\"}"))
            .andExpect(status().isOk()).andExpect(jsonPath("$.version").value(0));
        verify(service).set(1L,8L,true,null,"Approved");
    }
    @Test void deniedMutationAndBlankReasonDoNotReturnSuccess() throws Exception {
        var service=mock(DepartmentHeadDesignationService.class);
        when(service.set(anyLong(),anyLong(),anyBoolean(),any(),anyString())).thenThrow(new AccessDeniedException("Access denied."));
        var mvc=MockMvcBuilders.standaloneSetup(new DepartmentHeadDesignationController(service)).setControllerAdvice(new GlobalExceptionHandler()).build();
        mvc.perform(put("/api/admin/department-head-designations/1/8").contentType(MediaType.APPLICATION_JSON)
            .content("{\"active\":true,\"reason\":\"Approved\"}")).andExpect(status().isForbidden());
        mvc.perform(put("/api/admin/department-head-designations/1/8").contentType(MediaType.APPLICATION_JSON)
            .content("{\"active\":true,\"reason\":\" \"}")).andExpect(status().isBadRequest());
        verify(service,times(1)).set(anyLong(),anyLong(),anyBoolean(),any(),anyString());
    }
}
