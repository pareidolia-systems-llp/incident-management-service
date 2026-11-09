package com.pareidolia.incidentmanagement;

import com.pareidolia.incidentmanagement.controller.*;
import com.pareidolia.incidentmanagement.exception.GlobalExceptionHandler;
import com.pareidolia.incidentmanagement.service.*;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class IncidentSecurityAdministrationControllerTests {
    @Test void classificationEndpointValidatesAndDelegates() throws Exception {
        var service=mock(IncidentSecurityAdministrationService.class);
        when(service.classify(3L,"STANDARD",0L,"Reviewed")).thenReturn(new IncidentSecurityAdministrationService.ClassificationResult("STANDARD",1));
        var mvc=MockMvcBuilders.standaloneSetup(new IncidentSecurityAdministrationController(service)).setControllerAdvice(new GlobalExceptionHandler()).build();
        mvc.perform(put("/api/admin/incident-security/3/classification").contentType("application/json").content("{\"classification\":\"STANDARD\",\"expectedVersion\":0,\"reason\":\"Reviewed\"}")).andExpect(status().isOk()).andExpect(jsonPath("$.version").value(1));
        mvc.perform(put("/api/admin/incident-security/3/classification").contentType("application/json").content("{\"classification\":\"STANDARD\",\"expectedVersion\":0,\"reason\":\"\"}")).andExpect(status().isBadRequest());
        verify(service,times(1)).classify(anyLong(),anyString(),anyLong(),anyString());
    }
    @Test void caseGrantDeniedByServiceIsForbidden() throws Exception {
        var service=mock(IncidentSecurityAdministrationService.class);
        when(service.setGrant(anyLong(),anyLong(),anyString(),anyBoolean(),anyLong(),anyString())).thenThrow(new AccessDeniedException("denied"));
        var mvc=MockMvcBuilders.standaloneSetup(new IncidentSecurityAdministrationController(service)).setControllerAdvice(new GlobalExceptionHandler()).build();
        mvc.perform(put("/api/admin/incident-security/3/grants/7/VIEW").contentType("application/json").content("{\"active\":true,\"expectedVersion\":0,\"reason\":\"Approved\"}")).andExpect(status().isForbidden());
    }
}
