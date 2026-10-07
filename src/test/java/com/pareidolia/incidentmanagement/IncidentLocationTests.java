package com.pareidolia.incidentmanagement;

import com.pareidolia.incidentmanagement.controller.IncidentController;
import com.pareidolia.incidentmanagement.entity.AppUser;
import com.pareidolia.incidentmanagement.enums.AppUserRole;
import com.pareidolia.incidentmanagement.exception.GlobalExceptionHandler;
import com.pareidolia.incidentmanagement.mapper.IncidentMapper;
import com.pareidolia.incidentmanagement.repository.IncidentRepository;
import com.pareidolia.incidentmanagement.repository.IncidentHistoryRepository;
import com.pareidolia.incidentmanagement.service.AppUserService;
import com.pareidolia.incidentmanagement.service.IncidentService;
import com.pareidolia.incidentmanagement.service.impl.IncidentServiceImpl;
import com.pareidolia.incidentmanagement.enums.IncidentStatus;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import tools.jackson.databind.json.JsonMapper;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

// Isolated H2 persistence and real MVC validation/service/mapping; no production database or login.
@DataJpaTest
@Import({IncidentServiceImpl.class, IncidentMapper.class})
class IncidentLocationTests {
    @Autowired IncidentService service;
    @Autowired IncidentRepository repository;
    @Autowired IncidentHistoryRepository historyRepository;
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

    private void setStatus(long id, IncidentStatus status) {
        var incident = repository.findById(id).orElseThrow();
        incident.setStatus(status);
        if (status == IncidentStatus.VALIDATED) {
            incident.setValidatedBy("reviewer@example.test");
            incident.setValidatedAt(java.time.LocalDateTime.now());
        }
        repository.saveAndFlush(incident);
    }

    private void authenticateAs(String email, AppUserRole role) {
        AppUser actor = new AppUser();
        actor.setEmail(email);
        actor.setRole(role);
        when(users.getAuthenticatedUser()).thenReturn(actor);
    }

    private ResultActions close(long id) throws Exception {
        return mvc.perform(post("/api/incidents/{id}/close", id)
                .contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("remarks", "Reporter confirmed closure."))));
    }

    @ParameterizedTest
    @EnumSource(AppUserRole.class)
    void listReturnsNewestCreatedIncidentFirst(AppUserRole role) throws Exception {
        long a = create(request());
        long b = create(request());
        long c = create(request());
        setCreatedAt(a, "2026-01-01T10:00:00");
        setCreatedAt(b, "2026-01-02T10:00:00");
        setCreatedAt(c, "2026-01-03T10:00:00");
        authenticateAs("REPORTER@example.test", role);

        assertListOrder(c, b, a);

        // Prove createdAt takes precedence over ID (and reportedAt).
        setCreatedAt(a, "2026-01-04T10:00:00");
        assertListOrder(a, c, b);
    }

    @ParameterizedTest
    @EnumSource(AppUserRole.class)
    void listBreaksEqualCreationTimestampsByHigherIdFirst(AppUserRole role) throws Exception {
        long a = create(request());
        long b = create(request());
        setCreatedAt(a, "2026-01-01T10:00:00");
        setCreatedAt(b, "2026-01-01T10:00:00");
        assertThat(b).isGreaterThan(a);
        authenticateAs("reporter@example.test", role);

        assertListOrder(b, a);
    }

    @ParameterizedTest
    @EnumSource(AppUserRole.class)
    void listPreservesVisibilityAndResponseFields(AppUserRole role) throws Exception {
        Map<String, Object> body = request();
        body.put("deskNumber", "Desk D-214");
        long own = create(body);
        authenticateAs("other@example.test", AppUserRole.REPORTER);
        long other = create(request());
        setCreatedAt(own, "2026-01-01T10:00:00");
        setCreatedAt(other, "2026-01-02T10:00:00");
        authenticateAs("REPORTER@example.test", role);

        if (role == AppUserRole.REPORTER) {
            assertListOrder(own);
        } else {
            assertListOrder(other, own);
        }
        String detail = mvc.perform(get("/api/incidents/{id}", own))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.deskNumber").value("Desk D-214"))
                .andExpect(jsonPath("$.affectedSystem").value("Corporate VPN"))
                .andReturn().getResponse().getContentAsString();
        String list = mvc.perform(get("/api/incidents"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertThat(json.readTree(list).get(role == AppUserRole.REPORTER ? 0 : 1))
                .isEqualTo(json.readTree(detail));

        authenticateAs("nobody@example.test", AppUserRole.REPORTER);
        assertListOrder();
    }

    private void setCreatedAt(long id, String timestamp) {
        entityManager.flush();
        // createdAt is immutable through JPA; set exact persisted fixtures without sleeps.
        entityManager.createNativeQuery("update incidents set created_at = :timestamp where id = :id")
                .setParameter("timestamp", java.time.LocalDateTime.parse(timestamp))
                .setParameter("id", id).executeUpdate();
        entityManager.clear();
    }

    private void assertListOrder(long... ids) throws Exception {
        ResultActions result = mvc.perform(get("/api/incidents"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(ids.length));
        for (int i = 0; i < ids.length; i++) {
            result.andExpect(jsonPath("$[" + i + "].id").value(ids[i]));
        }
    }

    @Test
    void originalReporterClosesValidatedIncidentAndRecordsAuthenticatedActor() throws Exception {
        long id = create(request());
        setStatus(id, IncidentStatus.VALIDATED);

        authenticateAs(" REPORTER@example.test ", AppUserRole.REPORTER);
        close(id).andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("CLOSED"))
                .andExpect(jsonPath("$.closureConfirmedBy").value(" REPORTER@example.test "))
                .andExpect(jsonPath("$.closedAt").isNotEmpty());

        var history = historyRepository.findByIncidentIdOrderByChangedAtDesc(id);
        assertThat(history).filteredOn(entry -> entry.getActionType()
                == com.pareidolia.incidentmanagement.enums.HistoryActionType.INCIDENT_CLOSED)
                .singleElement().satisfies(entry -> {
                    assertThat(entry.getChangedBy()).isEqualTo(" REPORTER@example.test ");
                    assertThat(entry.getRemarks()).isEqualTo("Reporter confirmed closure.");
                    assertThat(entry.getNewValue()).isEqualTo("CLOSED");
                });
        entityManager.flush();
        entityManager.clear();
        var saved = repository.findById(id).orElseThrow();
        assertThat(saved.getClosureConfirmedBy()).isEqualTo(" REPORTER@example.test ");
        assertThat(saved.getClosedAt()).isNotNull();
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({
            "reviewer@example.test, REVIEWER",
            "handler@example.test, IT_HANDLER",
            "other@example.test, REPORTER",
            "admin@example.test, ADMIN"
    })
    void nonReporterCannotCloseValidatedIncident(String email, AppUserRole role) throws Exception {
        long id = create(request());
        setStatus(id, IncidentStatus.VALIDATED);
        authenticateAs(email, role);
        long historyCount = historyRepository.count();

        close(id).andExpect(status().isForbidden());
        assertThat(repository.findById(id).orElseThrow().getStatus()).isEqualTo(IncidentStatus.VALIDATED);
        assertThat(repository.findById(id).orElseThrow().getClosedAt()).isNull();
        assertThat(historyRepository.count()).isEqualTo(historyCount);
    }

    @Test
    void adminMayCloseOnlyWhenAdminIsAlsoOriginalReporter() throws Exception {
        long id = create(request());
        setStatus(id, IncidentStatus.VALIDATED);
        authenticateAs("reporter@example.test", AppUserRole.ADMIN);

        close(id).andExpect(status().isOk())
                .andExpect(jsonPath("$.closureConfirmedBy").value("reporter@example.test"));
    }

    @Test
    void originalReporterCannotCloseBeforeValidatedStatus() throws Exception {
        long id = create(request());
        authenticateAs("reporter@example.test", AppUserRole.REPORTER);

        close(id).andExpect(status().isConflict());
        assertThat(repository.findById(id).orElseThrow().getStatus()).isEqualTo(IncidentStatus.ASSIGNED);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   "})
    void missingReporterIdentityFailsClosed(String reportedBy) throws Exception {
        var incident = new com.pareidolia.incidentmanagement.entity.Incident();
        incident.setId(999L);
        incident.setReportedBy(reportedBy);
        incident.setStatus(IncidentStatus.VALIDATED);
        var isolatedRepository = mock(IncidentRepository.class);
        when(isolatedRepository.findById(999L)).thenReturn(java.util.Optional.of(incident));
        IncidentService isolatedService = new IncidentServiceImpl(
                isolatedRepository,
                mock(IncidentHistoryRepository.class),
                new IncidentMapper(),
                users,
                "owner@example.test"
        );
        MockMvc isolatedMvc = MockMvcBuilders.standaloneSetup(new IncidentController(isolatedService))
                .setControllerAdvice(new GlobalExceptionHandler()).build();
        authenticateAs("reporter@example.test", AppUserRole.REPORTER);

        isolatedMvc.perform(post("/api/incidents/{id}/close", 999L)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("remarks", "Reporter confirmed closure."))))
                .andExpect(status().isForbidden());
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
