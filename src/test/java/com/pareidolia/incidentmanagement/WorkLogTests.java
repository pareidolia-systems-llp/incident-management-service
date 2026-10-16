package com.pareidolia.incidentmanagement;

import com.pareidolia.incidentmanagement.controller.WorkLogController;
import com.pareidolia.incidentmanagement.entity.*;
import com.pareidolia.incidentmanagement.enums.AppUserRole;
import com.pareidolia.incidentmanagement.exception.GlobalExceptionHandler;
import com.pareidolia.incidentmanagement.repository.*;
import com.pareidolia.incidentmanagement.service.*;
import com.pareidolia.incidentmanagement.service.impl.WorkLogServiceImpl;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import tools.jackson.databind.json.JsonMapper;
import java.time.LocalDateTime;
import java.util.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@DataJpaTest
@Import({WorkLogServiceImpl.class, AppUserService.class})
class WorkLogTests {
    @Autowired WorkLogService service;
    @Autowired WorkLogRepository entries;
    @Autowired AppUserRepository users;
    @Autowired IncidentHistoryRepository history;
    @Autowired EntityManager entityManager;
    MockMvc mvc;
    final JsonMapper json = JsonMapper.builder().build();

    @BeforeEach void setup() {
        mvc = MockMvcBuilders.standaloneSetup(new WorkLogController(service))
                .setControllerAdvice(new GlobalExceptionHandler()).build();
    }
    @AfterEach void clear() { SecurityContextHolder.clearContext(); }

    AppUser user(String email, AppUserRole role) {
        AppUser user = new AppUser(); user.setEmail(email); user.setDisplayName("Work user"); user.setRole(role);
        return users.saveAndFlush(user);
    }
    void login(AppUser user) {
        OidcUser oidc = mock(OidcUser.class); when(oidc.getEmail()).thenReturn(user.getEmail());
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(oidc, null, List.of()));
    }
    Map<String, Object> request() {
        return new LinkedHashMap<>(Map.of("workedAt", "2026-10-15T15:40:00", "category", "MAINTENANCE",
                "summary", "  Checked backup jobs  ", "details", "  Verified completion  ", "durationMinutes", 30));
    }
    void create(Map<String, Object> request, int expected) throws Exception {
        mvc.perform(post("/api/work-logs").contentType("application/json").content(json.writeValueAsString(request)))
                .andExpect(status().is(expected));
    }

    @ParameterizedTest @EnumSource(AppUserRole.class)
    void roleMatrixCreatesWithSessionOwnerAndServerTimestampOnly(AppUserRole role) throws Exception {
        AppUser actor = user("worker@example.test", role); login(actor);
        boolean permitted = role == AppUserRole.ADMIN || role == AppUserRole.IT_HANDLER;
        LocalDateTime before = LocalDateTime.now();
        create(request(), permitted ? 201 : 403);
        mvc.perform(get("/api/work-logs")).andExpect(status().is(permitted ? 200 : 403));
        entityManager.flush(); entityManager.clear();
        assertThat(entries.count()).isEqualTo(permitted ? 1 : 0);
        if (permitted) {
            WorkLogEntry entry = entries.findAll().get(0);
            assertThat(entry.getOwner().getId()).isEqualTo(actor.getId());
            assertThat(entry.getSummary()).isEqualTo("Checked backup jobs");
            assertThat(entry.getDetails()).isEqualTo("Verified completion");
            assertThat(entry.getCategory()).isEqualTo("MAINTENANCE");
            assertThat(entry.getWorkedAt()).isEqualTo(LocalDateTime.parse("2026-10-15T15:40:00"));
            assertThat(entry.getCreatedAt()).isBetween(before.minusSeconds(1), LocalDateTime.now().plusSeconds(1));
        }
        assertThat(users.count()).isEqualTo(1);
        assertThat(history.count()).isZero();
    }

    @Test void clientsCannotSubmitOwnerOrServerControlledFieldsOrFilterAnotherOwner() throws Exception {
        AppUser actor = user("worker@example.test", AppUserRole.IT_HANDLER);
        AppUser other = user("other@example.test", AppUserRole.ADMIN); login(actor);
        for (String field : List.of("ownerId", "owner_id", "owner", "ownerEmail", "owner_email", "created_by", "createdBy", "createdAt", "created_at", "id")) {
            var request = request(); request.put(field, other.getId()); create(request, 400);
        }
        assertThat(entries.count()).isZero();
        create(request(), 201);
        assertThat(entries.findAll().get(0).getOwner().getId()).isEqualTo(actor.getId());
        mvc.perform(get("/api/work-logs?ownerId=" + other.getId())).andExpect(status().isBadRequest());
        assertThat(users.count()).isEqualTo(2);
    }

    @Test void ownEntriesOnlyIncludingAdminAndDeterministicWorkedTimeIdOrdering() throws Exception {
        AppUser first = user("first@example.test", AppUserRole.IT_HANDLER);
        AppUser second = user("second@example.test", AppUserRole.ADMIN);
        login(first);
        var early = request(); early.put("workedAt", "2026-10-14T09:00:00"); early.put("summary", "Early"); create(early, 201);
        var late = request(); late.put("summary", "Late first"); create(late, 201);
        var tie = request(); tie.put("summary", "Late second"); create(tie, 201);
        login(second);
        var other = request(); other.put("summary", "Admin private work"); create(other, 201);
        mvc.perform(get("/api/work-logs")).andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.length()").value(1)).andExpect(jsonPath("$[0].summary").value("Admin private work"))
                .andExpect(jsonPath("$[0].ownerId").doesNotExist());
        login(first);
        mvc.perform(get("/api/work-logs")).andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(3))
                .andExpect(jsonPath("$[0].summary").value("Late second"))
                .andExpect(jsonPath("$[1].summary").value("Late first"))
                .andExpect(jsonPath("$[2].summary").value("Early"));
    }

    @Test void validationRejectsInvalidFieldsAndAllowsOptionalDetailsAndDuration() throws Exception {
        login(user("worker@example.test", AppUserRole.IT_HANDLER));
        for (var invalid : List.of(Map.entry("summary", "  "), Map.entry("summary", "x".repeat(256)),
                Map.entry("details", "x".repeat(8001)), Map.entry("category", "UNSUPPORTED"),
                Map.entry("category", ""), Map.entry("durationMinutes", 0), Map.entry("durationMinutes", -1),
                Map.entry("workedAt", ""), Map.entry("workedAt", "2026-02-30T09:00:00"))) {
            var request = request(); request.put(invalid.getKey(), invalid.getValue()); create(request, 400);
        }
        for (String required : List.of("summary", "category", "workedAt")) {
            var request = request(); request.remove(required); create(request, 400);
        }
        assertThat(entries.count()).isZero();
        var minimal = request(); minimal.remove("details"); minimal.remove("durationMinutes"); create(minimal, 201);
        assertThat(entries.findAll().get(0).getDurationMinutes()).isNull();
        assertThat(entries.findAll().get(0).getDetails()).isNull();
    }

    @Test void inactiveOrMissingAuthenticatedUserCannotAccessWorkLogs() throws Exception {
        mvc.perform(get("/api/work-logs")).andExpect(status().isForbidden());
        var inactive = user("inactive@example.test", AppUserRole.ADMIN);
        inactive.setActive(false); users.saveAndFlush(inactive); login(inactive);
        mvc.perform(get("/api/work-logs")).andExpect(status().isForbidden());
        create(request(), 403);
    }

    @Test void noEditingOrDeletionEndpoints() throws Exception {
        login(user("worker@example.test", AppUserRole.ADMIN));
        mvc.perform(put("/api/work-logs/1").contentType("application/json").content("{}")).andExpect(status().isNotFound());
        mvc.perform(delete("/api/work-logs/1")).andExpect(status().isNotFound());
    }
}
