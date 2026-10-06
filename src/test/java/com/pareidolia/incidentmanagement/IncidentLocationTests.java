package com.pareidolia.incidentmanagement;

import com.pareidolia.incidentmanagement.controller.IncidentController;
import com.pareidolia.incidentmanagement.entity.AppUser;
import com.pareidolia.incidentmanagement.enums.AppUserRole;
import com.pareidolia.incidentmanagement.exception.GlobalExceptionHandler;
import com.pareidolia.incidentmanagement.mapper.IncidentMapper;
import com.pareidolia.incidentmanagement.repository.IncidentRepository;
import com.pareidolia.incidentmanagement.service.AppUserService;
import com.pareidolia.incidentmanagement.service.IncidentService;
import com.pareidolia.incidentmanagement.service.impl.IncidentServiceImpl;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import tools.jackson.databind.json.JsonMapper;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

// Isolated H2 persistence and real MVC validation/service/mapping; no production database or login.
@DataJpaTest
@Import({IncidentServiceImpl.class, IncidentMapper.class})
class IncidentLocationTests {
    @Autowired IncidentService service;
    @Autowired IncidentRepository repository;
    @Autowired EntityManager entityManager;
    @MockitoBean AppUserService users;
    private MockMvc mvc;
    private final JsonMapper json = JsonMapper.builder().build();

    @BeforeEach
    void setUp() {
        AppUser reporter = new AppUser();
        reporter.setEmail("reporter@example.test");
        reporter.setRole(AppUserRole.REPORTER);
        when(users.getAuthenticatedUser()).thenReturn(reporter);
        mvc = MockMvcBuilders.standaloneSetup(new IncidentController(service))
                .setControllerAdvice(new GlobalExceptionHandler()).build();
    }

    private Map<String, Object> request() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("title", "VPN disconnecting");
        body.put("description", "VPN disconnects during work");
        body.put("issueType", "IT_ISSUE");
        body.put("category", "Network / Connectivity");
        body.put("severity", "LOW");
        body.put("priority", "LOW");
        body.put("affectedSystem", "Corporate VPN");
        return body;
    }

    private long create(Map<String, Object> body) throws Exception {
        String response = mvc.perform(post("/api/incidents").contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(body)))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        return json.readTree(response).get("id").asLong();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"Desk D-214", "0012"})
    void deskNumberRoundTripsThroughCreateDatabaseAndGet(String desk) throws Exception {
        Map<String, Object> body = request();
        if (desk != null) body.put("deskNumber", desk); // also test omitted optional field
        long id = create(body);
        entityManager.flush();
        entityManager.clear();
        assertThat(repository.findById(id).orElseThrow().getDeskNumber()).isEqualTo(desk);
        String response = mvc.perform(get("/api/incidents/{id}", id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.reportedBy").value("reporter@example.test"))
                .andExpect(jsonPath("$.affectedSystem").value("Corporate VPN"))
                .andReturn().getResponse().getContentAsString();
        assertThat(json.readTree(response).get("deskNumber").isNull() ? null
                : json.readTree(response).get("deskNumber").asText()).isEqualTo(desk);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t\n"})
    void rejectsNullEmptyAndWhitespaceAffectedSystem(String affected) throws Exception {
        Map<String, Object> body = request();
        body.put("affectedSystem", affected);
        mvc.perform(post("/api/incidents").contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(body)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.affectedSystem").exists());
        assertThat(repository.count()).isZero();
    }

    @Test
    void rejectsMissingAffectedSystem() throws Exception {
        Map<String, Object> body = request();
        body.remove("affectedSystem");
        mvc.perform(post("/api/incidents").contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(body)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.affectedSystem").exists());
    }

    @Test
    void legacyIncidentWithNullLocationFieldsRemainsReadable() throws Exception {
        long id = create(request());
        entityManager.flush();
        entityManager.createNativeQuery("update incidents set affected_system = null, desk_number = null where id = :id")
                .setParameter("id", id).executeUpdate();
        entityManager.clear();
        mvc.perform(get("/api/incidents/{id}", id)).andExpect(status().isOk())
                .andExpect(jsonPath("$.deskNumber").doesNotExist())
                .andExpect(jsonPath("$.affectedSystem").doesNotExist());
    }
}
