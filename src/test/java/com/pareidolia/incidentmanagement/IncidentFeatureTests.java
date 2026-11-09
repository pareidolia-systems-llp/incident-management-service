package com.pareidolia.incidentmanagement;

import com.pareidolia.incidentmanagement.controller.*;
import com.pareidolia.incidentmanagement.dto.*;
import com.pareidolia.incidentmanagement.entity.*;
import com.pareidolia.incidentmanagement.enums.*;
import com.pareidolia.incidentmanagement.exception.*;
import com.pareidolia.incidentmanagement.mapper.IncidentMapper;
import com.pareidolia.incidentmanagement.repository.*;
import com.pareidolia.incidentmanagement.security.IncidentReadSnapshot;
import com.pareidolia.incidentmanagement.security.IncidentSecurityGate;
import org.springframework.test.context.jdbc.Sql;
import com.pareidolia.incidentmanagement.service.*;
import com.pareidolia.incidentmanagement.service.impl.*;
import jakarta.persistence.EntityManager;
import org.apache.poi.ss.usermodel.CellType;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.hibernate.resource.jdbc.spi.StatementInspector;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.*;
import java.time.LocalDateTime;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@DataJpaTest(properties = "spring.jpa.properties.hibernate.session_factory.statement_inspector=com.pareidolia.incidentmanagement.IncidentFeatureTests$SqlCapture")
@Import({IncidentServiceImpl.class, IncidentMapper.class, IncidentAttachmentServiceImpl.class, IncidentReportServiceImpl.class,
        IncidentSecurityGate.class, IncidentReadSnapshot.class})
@Sql(scripts = "/rollback-confidentiality-schema.sql", executionPhase = Sql.ExecutionPhase.BEFORE_TEST_CLASS)
class IncidentFeatureTests {
    @Autowired IncidentRepository incidents;
    @Autowired IncidentHistoryRepository history;
    @Autowired IncidentAttachmentRepository attachments;
    @Autowired IncidentAttachmentService attachmentService;
    @Autowired IncidentReportService reportService;
    @Autowired IncidentService incidentService;
    @Autowired AppUserRepository appUsers;
    @Autowired EntityManager entityManager;
    @Autowired org.springframework.jdbc.core.JdbcTemplate db;
    @MockitoBean AppUserService users;
    MockMvc mvc;

    public static class SqlCapture implements StatementInspector {
        static final List<String> statements = new ArrayList<>();
        @Override public String inspect(String sql) { statements.add(sql); return sql; }
    }

    @BeforeEach void setup() {
        actor(AppUserRole.ADMIN, "owner@pareidolia.in");
        mvc = MockMvcBuilders.standaloneSetup(new IncidentAttachmentController(attachmentService),
                new IncidentReportController(reportService), new IncidentController(incidentService))
                .setControllerAdvice(new GlobalExceptionHandler()).build();
    }

    void actor(AppUserRole role, String email) {
        AppUser user = new AppUser(); user.setRole(role); user.setEmail(email);
        when(users.getAuthenticatedUser()).thenReturn(user);
    }

    Incident incident(String number, String date) {
        Incident incident = new Incident();
        incident.setIncidentNumber(number); incident.setReportedAt(LocalDateTime.parse(date));
        incident.setReportedBy("owner@pareidolia.in"); incident.setTitle("=1+1"); incident.setDescription("Test description\nsecond line");
        incident.setIssueType(IssueType.IT_ISSUE); incident.setSeverity(Severity.LOW); incident.setPriority(Priority.LOW);
        incident.setStatus(IncidentStatus.ASSIGNED);
        return incidents.saveAndFlush(incident);
    }

    @Test
    void persistedRestrictedCaseStaysHiddenFromLegacyAdminAndBothExportSheets() throws Exception {
        Incident restricted = incident("INC-RESTRICTED", "2026-10-05T12:00:00");
        Incident ordinary = incident("INC-STANDARD", "2026-10-05T12:00:00");
        var attachment = attachmentService.upload(restricted.getId(), List.of(image("png"))).get(0);
        for (Incident ticket : List.of(restricted, ordinary)) {
            var event = new IncidentHistory();
            event.setIncident(ticket);
            event.setActionType(HistoryActionType.WORK_NOTE);
            event.setChangedBy("owner@pareidolia.in");
            event.setChangedAt(LocalDateTime.parse("2026-10-05T13:00:00"));
            history.saveAndFlush(event);
        }
        db.update("insert into incident_security_classification values (?, 'RESTRICTED', 1)", restricted.getId());
        db.update("insert into incident_security_classification values (?, 'STANDARD', 1)", ordinary.getId());
        var admin = new AppUser();
        admin.setId(123L);
        admin.setRole(AppUserRole.ADMIN);
        admin.setEmail("admin@example.test");
        when(users.getAuthenticatedUser()).thenReturn(admin);
        db.update("insert into assignment_admin_capabilities values (?, 'GLOBAL_INCIDENT_VIEW', 1)", admin.getId());

        mvc.perform(get("/api/incidents")).andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].incidentNumber").value("INC-STANDARD"));
        mvc.perform(get("/api/incidents").param("page", "0").param("size", "10")).andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].incidentNumber").value("INC-STANDARD"));
        for (String url : List.of("/api/incidents/" + restricted.getId(),
                "/api/incidents/number/" + restricted.getIncidentNumber(),
                "/api/incidents/" + restricted.getId() + "/history",
                "/api/incidents/" + restricted.getId() + "/attachments",
                "/api/incidents/" + restricted.getId() + "/attachments/" + attachment.id())) {
            mvc.perform(get(url)).andExpect(status().isNotFound());
        }
        var export = mvc.perform(get("/api/reports/incidents/monthly").param("year", "2026").param("month", "10"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray();
        try (var workbook = new XSSFWorkbook(new ByteArrayInputStream(export))) {
            for (String name : List.of("Incidents", "Lifecycle History")) {
                var sheet = workbook.getSheet(name);
                assertThat(sheet.getPhysicalNumberOfRows()).isEqualTo(2);
                assertThat(sheet.getRow(1).getCell(0).getStringCellValue()).isEqualTo("INC-STANDARD");
            }
        }
    }

    @Test
    void restrictedOriginalReporterNeedsVerifiedIdentityAndCaseViewForLifecycle() throws Exception {
        Incident restricted = incident("INC-REPORTER-RESTRICTED", "2026-10-05T12:00:00");
        restricted.setStatus(IncidentStatus.RESOLVED);
        incidents.saveAndFlush(restricted);
        db.update("insert into incident_security_classification values (?, 'RESTRICTED', 1)", restricted.getId());
        var actor = new AppUser();
        actor.setId(124L);
        actor.setRole(AppUserRole.REPORTER);
        actor.setEmail(restricted.getReportedBy());
        when(users.getAuthenticatedUser()).thenReturn(actor);
        var oidc = org.mockito.Mockito.mock(org.springframework.security.oauth2.core.oidc.user.OidcUser.class);
        when(oidc.getEmail()).thenReturn(actor.getEmail());
        when(oidc.getEmailVerified()).thenReturn(true);
        org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(
                new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(oidc, "", List.of()));
        try {
            String path = "/api/incidents/" + restricted.getId();
            mvc.perform(get(path)).andExpect(status().isNotFound());
            mvc.perform(post(path + "/validate").contentType("application/json")
                    .content("{\"validationDetails\":\"Verified\"}")).andExpect(status().isNotFound());

            db.update("insert into incident_security_grants values (?, ?, 'VIEW', 1)", restricted.getId(), actor.getId());
            when(oidc.getEmailVerified()).thenReturn(false);
            mvc.perform(get(path)).andExpect(status().isNotFound());
            when(oidc.getEmailVerified()).thenReturn(true);
            mvc.perform(get(path)).andExpect(status().isOk());
            mvc.perform(multipart(path + "/attachments").file(image("png"))).andExpect(status().isNotFound());
            mvc.perform(post(path + "/validate").contentType("application/json")
                    .content("{\"validationDetails\":\"Verified\"}")).andExpect(status().isOk());
            mvc.perform(post(path + "/close").contentType("application/json")
                    .content("{\"remarks\":\"Confirmed closure\"}")).andExpect(status().isOk());

            db.update("update incident_security_grants set active = 0 where incident_id = ?", restricted.getId());
            mvc.perform(get(path)).andExpect(status().isNotFound());
        } finally {
            org.springframework.security.core.context.SecurityContextHolder.clearContext();
        }
    }

    @Test
    void unverifiableClassificationFailsClosedForLegacyReadsAndExport() throws Exception {
        Incident ticket = incident("INC-UNVERIFIABLE", "2026-10-05T12:00:00");
        db.update("insert into incident_security_classification values (?, 'RESTRICTED', 0)", ticket.getId());
        for (String url : List.of("/api/incidents", "/api/incidents/" + ticket.getId(),
                "/api/incidents/" + ticket.getId() + "/attachments")) {
            mvc.perform(get(url)).andExpect(status().isServiceUnavailable());
        }
        mvc.perform(get("/api/reports/incidents/monthly").param("year", "2026").param("month", "10"))
                .andExpect(status().isServiceUnavailable());
    }

    MockMultipartFile image(String format) throws IOException {
        var bytes = new ByteArrayOutputStream();
        ImageIO.write(new BufferedImage(3, 3, BufferedImage.TYPE_INT_RGB), format, bytes);
        // Filename and claimed MIME must not control detected type.
        return new MockMultipartFile("files", "../../error\r\n.html", "text/html", bytes.toByteArray());
    }

    @Test
    void reporterFeedbackThenScreenshotUsesNormalAttachmentHistory() throws Exception {
        var ticket = incident("FEEDBACK-IMAGE", "2026-10-01T00:00:00");
        ticket.setStatus(IncidentStatus.RESOLVED);
        incidents.saveAndFlush(ticket);
        actor(AppUserRole.REPORTER, ticket.getReportedBy());
        mvc.perform(post("/api/incidents/{id}/resolution-feedback", ticket.getId())
                .contentType("application/json").content("{\"feedback\":\"Still disconnected\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("IN_PROGRESS"));
        mvc.perform(multipart("/api/incidents/{id}/attachments", ticket.getId()).file(image("png")))
                .andExpect(status().isCreated());
        entityManager.flush(); entityManager.clear();
        assertThat(incidents.findById(ticket.getId()).orElseThrow().getStatus()).isEqualTo(IncidentStatus.IN_PROGRESS);
        var events = history.findByIncidentIdOrderByChangedAtAscIdAsc(ticket.getId());
        assertThat(events).extracting(e -> e.getActionType()).containsExactly(
                HistoryActionType.RESOLUTION_NOT_ACCEPTED, HistoryActionType.STATUS_CHANGED, HistoryActionType.ATTACHMENT_ADDED);
        mvc.perform(get("/api/incidents/{id}/attachments", ticket.getId()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(1));
    }

    @ParameterizedTest
    @EnumSource(value = AppUserRole.class, names = {"IT_HANDLER", "ADMIN"})
    void reassessmentsRequireReasonAndRetainAuditedChanges(AppUserRole role) throws Exception {
        var ticket = incident("REASSESS", "2026-10-01T00:00:00");
        actor(role, "operator@pareidolia.in");
        for (String field : List.of("severity", "priority")) {
            for (String reasonJson : List.of("", ",\"remarks\":\"\"", ",\"remarks\":\"   \"")) {
                mvc.perform(post("/api/incidents/{id}/" + field, ticket.getId())
                        .contentType("application/json").content("{\"" + field + "\":\"HIGH\"" + reasonJson + "}"))
                        .andExpect(status().isBadRequest()).andExpect(jsonPath("$.fieldErrors.remarks").exists());
            }
            assertThat(history.findByIncidentIdOrderByChangedAtAscIdAsc(ticket.getId()))
                    .noneMatch(e -> e.getActionType().name().equals(field.toUpperCase() + "_CHANGED"));
            mvc.perform(post("/api/incidents/{id}/" + field, ticket.getId())
                    .contentType("application/json").content("{\"" + field + "\":\"HIGH\",\"remarks\":\"Business process blocked\"}"))
                    .andExpect(status().isOk()).andExpect(jsonPath("$." + field).value("HIGH"));
            var events = history.findByIncidentIdOrderByChangedAtAscIdAsc(ticket.getId());
            assertThat(events).filteredOn(e -> e.getActionType().name().equals(field.toUpperCase() + "_CHANGED"))
                    .singleElement().satisfies(e -> {
                        assertThat(e.getOldValue()).isEqualTo("LOW");
                        assertThat(e.getNewValue()).isEqualTo("HIGH");
                        assertThat(e.getRemarks()).isEqualTo("Business process blocked");
                        assertThat(e.getChangedBy()).isEqualTo("operator@pareidolia.in");
                        assertThat(e.getChangedAt()).isNotNull();
                    });
        }
        assertThat(incidents.findById(ticket.getId()).orElseThrow().getStatus()).isEqualTo(IncidentStatus.ASSIGNED);
    }

    @ParameterizedTest @EnumSource(AppUserRole.class)
    void workNotePermissionsPersistenceAndIdentity(AppUserRole role) throws Exception {
        var ticket = incident("NOTE", "2026-10-01T00:00:00");
        actor(role, "operator@pareidolia.in");
        boolean permitted = role == AppUserRole.ADMIN || role == AppUserRole.IT_HANDLER;
        mvc.perform(post("/api/incidents/{id}/work-notes", ticket.getId())
                .contentType("application/json").content("{\"remarks\":\"  Checked VPN logs.  \"}"))
                .andExpect(status().is(permitted ? 201 : 403));
        entityManager.flush(); entityManager.clear();
        var events = history.findByIncidentIdOrderByChangedAtAscIdAsc(ticket.getId());
        assertThat(events).hasSize(permitted ? 1 : 0);
        if (permitted) {
            assertThat(events.get(0).getActionType()).isEqualTo(HistoryActionType.WORK_NOTE);
            assertThat(events.get(0).getRemarks()).isEqualTo("Checked VPN logs.");
            assertThat(events.get(0).getChangedBy()).isEqualTo("operator@pareidolia.in");
            assertThat(events.get(0).getChangedAt()).isNotNull();
            assertThat(events.get(0).getOldValue()).isNull();
            assertThat(events.get(0).getNewValue()).isNull();
        }
        assertThat(incidents.findById(ticket.getId()).orElseThrow().getStatus()).isEqualTo(IncidentStatus.ASSIGNED);
    }

    @Test void workNoteValidationAndClosedIncidentRules() throws Exception {
        var ticket = incident("NOTE-VALIDATION", "2026-10-01T00:00:00");
        for (String note : List.of("   ", "x".repeat(8001))) {
            mvc.perform(post("/api/incidents/{id}/work-notes", ticket.getId()).contentType("application/json")
                    .content("{\"remarks\":\"" + note + "\"}")).andExpect(status().isBadRequest());
        }
        ticket.setStatus(IncidentStatus.CLOSED); incidents.saveAndFlush(ticket);
        mvc.perform(post("/api/incidents/{id}/work-notes", ticket.getId()).contentType("application/json")
                .content("{\"remarks\":\"Checked logs\"}")).andExpect(status().isConflict());
        assertThat(history.count()).isZero();
    }

    @Test void reporterRejectionAttentionSurvivesWorkAndClearsOnResolutionWithoutLosingHistory() {
        var ticket = incident("REOPEN", "2026-10-01T00:00:00");
        var ordinary = incident("ORDINARY", "2026-10-01T00:00:00");
        ordinary.setStatus(IncidentStatus.IN_PROGRESS); incidents.saveAndFlush(ordinary);
        var resolve = new ResolveIncidentRequestDto(); resolve.setResolutionDetails("VPN profile recreated");
        incidentService.resolveIncident(ticket.getId(), resolve);
        var feedback = new ResolutionFeedbackRequestDto(); feedback.setFeedback("Still disconnected");
        actor(AppUserRole.IT_HANDLER, "handler@pareidolia.in");
        assertThatThrownBy(() -> incidentService.submitResolutionFeedback(ticket.getId(), feedback))
                .isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
        actor(AppUserRole.REPORTER, "owner@pareidolia.in");
        var reopened = incidentService.submitResolutionFeedback(ticket.getId(), feedback);
        assertThat(reopened.getStatus()).isEqualTo(IncidentStatus.IN_PROGRESS);
        assertThat(reopened.isIssueStillPersists()).isTrue();
        assertThat(reopened.getIssueStillPersistsReportedBy()).isEqualTo("owner@pareidolia.in");
        assertThat(reopened.getIssueStillPersistsAt()).isNotNull();
        actor(AppUserRole.IT_HANDLER, "handler@pareidolia.in");
        incidentService.addWorkNote(ticket.getId(), new AddWorkNoteRequestDto("Rechecked gateway logs"));
        var investigation = new UpdateInvestigationRequestDto(); investigation.setInvestigationDetails("Expired certificate");
        assertThat(incidentService.updateInvestigation(ticket.getId(), investigation).isIssueStillPersists()).isTrue();
        assertThat(incidentService.getAllIncidents().stream().filter(IncidentResponseDto::isIssueStillPersists)).hasSize(1);
        assertThat(incidentService.getIncident(ordinary.getId()).isIssueStillPersists()).isFalse();
        var resolved = incidentService.resolveIncident(ticket.getId(), resolve);
        assertThat(resolved.getStatus()).isEqualTo(IncidentStatus.RESOLVED);
        assertThat(resolved.isIssueStillPersists()).isFalse();
        assertThat(resolved.getIssueStillPersistsAt()).isNull();
        assertThat(incidentService.getAllIncidents()).noneMatch(IncidentResponseDto::isIssueStillPersists);
        assertThat(incidentService.getIncidentHistory(ticket.getId())).anySatisfy(event -> {
            assertThat(event.getActionType()).isEqualTo(HistoryActionType.RESOLUTION_NOT_ACCEPTED);
            assertThat(event.getRemarks()).contains("Still disconnected");
        });
        actor(AppUserRole.REPORTER, "other@pareidolia.in");
        assertThatThrownBy(() -> incidentService.getIncidentHistory(ticket.getId()))
                .isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
    }

    @Test void historyAndAttentionUseIdTieBreakerForEqualTimestamps() {
        var ticket = incident("TIE", "2026-10-01T00:00:00");
        ticket.setStatus(IncidentStatus.IN_PROGRESS); incidents.saveAndFlush(ticket);
        for (var action : List.of(HistoryActionType.RESOLUTION_NOT_ACCEPTED, HistoryActionType.INCIDENT_RESOLVED)) {
            var event = new IncidentHistory(); event.setIncident(ticket); event.setActionType(action);
            event.setChangedBy("owner@pareidolia.in"); event.setChangedAt(LocalDateTime.parse("2026-10-01T01:00:00"));
            history.saveAndFlush(event);
        }
        assertThat(incidentService.getIncident(ticket.getId()).isIssueStillPersists()).isFalse();
        assertThat(incidentService.getIncidentHistory(ticket.getId())).extracting(IncidentHistoryResponseDto::getActionType)
                .containsExactly(HistoryActionType.RESOLUTION_NOT_ACCEPTED, HistoryActionType.INCIDENT_RESOLVED);
    }

    @Test void reportUsesHalfOpenReportedDateRangeAndProducesReadableWorkbook() throws Exception {
        incident("BEFORE", "2026-09-30T23:59:59");
        var first = incident("FIRST", "2026-10-01T00:00:00");
        incident("LAST", "2026-10-31T23:59:59");
        incident("AFTER", "2026-11-01T00:00:00");
        AppUser reporter = new AppUser(); reporter.setEmail("owner@pareidolia.in"); reporter.setDisplayName("Reporter Name"); appUsers.saveAndFlush(reporter);
        IncidentHistory event = new IncidentHistory(); event.setIncident(first); event.setActionType(HistoryActionType.OWNER_ASSIGNED);
        event.setChangedBy("SYSTEM"); event.setRemarks("Assigned automatically"); history.saveAndFlush(event);
        var response = mvc.perform(get("/api/reports/incidents/monthly?year=2026&month=10"))
                .andExpect(status().isOk()).andExpect(header().string("Content-Disposition", "attachment; filename=\"incident-report-2026-10.xlsx\""))
                .andExpect(content().contentType("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
                .andReturn().getResponse();
        try (var workbook = new XSSFWorkbook(new ByteArrayInputStream(response.getContentAsByteArray()))) {
            var sheet = workbook.getSheet("Incidents");
            assertThat(sheet.getLastRowNum()).isEqualTo(2);
            assertThat(sheet.getRow(0).getCell(0).getStringCellValue()).isEqualTo("Incident / Ticket Number");
            assertThat(sheet.getRow(1).getCell(0).getStringCellValue()).isEqualTo("FIRST");
            assertThat(sheet.getRow(2).getCell(0).getStringCellValue()).isEqualTo("LAST");
            assertThat(sheet.getRow(1).getCell(2).getStringCellValue()).isEqualTo("Reporter Name");
            assertThat(sheet.getRow(1).getCell(6).getCellType()).isEqualTo(CellType.STRING);
            assertThat(sheet.getRow(1).getCell(6).getStringCellValue()).isEqualTo("=1+1");
            assertThat(sheet.getRow(1).getCell(1).getCellType()).isEqualTo(CellType.NUMERIC);
            assertThat(sheet.getPaneInformation().isFreezePane()).isTrue();
            assertThat(workbook.getFontAt(sheet.getRow(0).getCell(0).getCellStyle().getFontIndex()).getBold()).isTrue();
            assertThat(workbook.getSheet("Lifecycle History").getLastRowNum()).isEqualTo(1);
        }
        assertThat(history.count()).isEqualTo(1); // Export creates no incident audit event.
    }

    @ParameterizedTest @EnumSource(AppUserRole.class)
    void reportRolesAreEnforcedByServiceThroughApi(AppUserRole role) throws Exception {
        actor(role, "owner@pareidolia.in");
        mvc.perform(get("/api/reports/incidents/monthly?year=2026&month=10"))
                .andExpect(status().is(role == AppUserRole.ADMIN || role == AppUserRole.IT_HANDLER ? 200 : 403));
    }

    @Test void emptyMonthAndInvalidParameters() throws Exception {
        try (var workbook = new XSSFWorkbook(new ByteArrayInputStream(reportService.monthly(2026, 12)))) {
            assertThat(workbook.getSheetAt(0).getLastRowNum()).isZero();
        }
        for (String query : List.of("year=2026&month=0", "year=2026&month=13", "year=0&month=1",
                "year=9999&month=1", "year=no&month=1", "year=2026")) {
            mvc.perform(get("/api/reports/incidents/monthly?" + query)).andExpect(status().isBadRequest());
        }
    }

    private List<String> reportTickets(String query) throws Exception {
        byte[] bytes = mvc.perform(get("/api/reports/incidents/monthly?" + query))
                .andExpect(status().isOk()).andExpect(header().string("Cache-Control", "no-store"))
                .andReturn().getResponse().getContentAsByteArray();
        try (var workbook = new XSSFWorkbook(new ByteArrayInputStream(bytes))) {
            var sheet = workbook.getSheet("Incidents");
            List<String> tickets = new ArrayList<>();
            for (int row = 1; row <= sheet.getLastRowNum(); row++) tickets.add(sheet.getRow(row).getCell(0).getStringCellValue());
            return tickets;
        }
    }

    @Test void dateOnlyReportIncludesEntireSelectedDaysAndFullHistoryOfMatchingTickets() throws Exception {
        incident("BEFORE-RANGE", "2026-09-30T23:59:59.999999");
        var first = incident("RANGE-START", "2026-10-01T00:00:00");
        incident("RANGE-END", "2026-10-15T23:59:59.999999");
        incident("AFTER-RANGE", "2026-10-16T00:00:00");
        var event = new IncidentHistory(); event.setIncident(first); event.setActionType(HistoryActionType.WORK_NOTE);
        event.setRemarks("Later work is still included for matching incidents"); event.setChangedBy("owner@pareidolia.in");
        event.setChangedAt(LocalDateTime.parse("2026-10-20T12:00:00")); history.saveAndFlush(event);
        String query = "fromDate=2026-10-01&toDate=2026-10-15";
        assertThat(reportTickets(query)).containsExactly("RANGE-START", "RANGE-END");
        byte[] bytes = mvc.perform(get("/api/reports/incidents/monthly?" + query)).andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", "attachment; filename=\"incident-report-2026-10-01-to-2026-10-15.xlsx\""))
                .andReturn().getResponse().getContentAsByteArray();
        try (var workbook = new XSSFWorkbook(new ByteArrayInputStream(bytes))) {
            assertThat(workbook.getSheet("Lifecycle History").getLastRowNum()).isEqualTo(1);
            assertThat(workbook.getSheet("Lifecycle History").getRow(1).getCell(6).getStringCellValue())
                    .isEqualTo(event.getRemarks());
        }
        assertThat(history.count()).isEqualTo(1);
    }

    @Test void sameDayTimesUseExactInclusiveBoundariesAndPermitEqualEndpoints() throws Exception {
        incident("BEFORE-TIME", "2026-10-15T08:59:59.999999");
        incident("TIME-START", "2026-10-15T09:00:00");
        incident("TIME-END", "2026-10-15T17:30:00");
        incident("AFTER-TIME", "2026-10-15T17:30:00.000001");
        assertThat(reportTickets("fromDate=2026-10-15&fromTime=09:00&toDate=2026-10-15&toTime=17:30"))
                .containsExactly("TIME-START", "TIME-END");
        assertThat(reportTickets("fromDate=2026-10-15&fromTime=09:00&toDate=2026-10-15&toTime=09:00"))
                .containsExactly("TIME-START");
    }

    @Test void multiDayTimesAndIndependentlyOptionalTimesAreSupported() throws Exception {
        incident("DAY-START", "2026-10-14T00:00:00");
        incident("AFTERNOON", "2026-10-14T16:00:00");
        incident("NEXT-MORNING", "2026-10-15T10:00:00");
        incident("LAST-FRACTION", "2026-10-15T23:59:59.999999");
        assertThat(reportTickets("fromDate=2026-10-14&fromTime=16:00&toDate=2026-10-15&toTime=10:00"))
                .containsExactly("AFTERNOON", "NEXT-MORNING");
        assertThat(reportTickets("fromDate=2026-10-14&fromTime=16:00&toDate=2026-10-15"))
                .containsExactly("AFTERNOON", "NEXT-MORNING", "LAST-FRACTION");
        assertThat(reportTickets("fromDate=2026-10-14&toDate=2026-10-15&toTime=10:00"))
                .containsExactly("DAY-START", "AFTERNOON", "NEXT-MORNING");
    }

    @Test void reportRejectsInvalidOrAmbiguousRangesWithoutSwapping() throws Exception {
        for (String query : List.of("fromDate=2026-10-16&toDate=2026-10-15",
                "fromDate=2026-10-15&fromTime=17:30&toDate=2026-10-15&toTime=09:00")) {
            mvc.perform(get("/api/reports/incidents/monthly?" + query)).andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.message").value("From date/time must be on or before To date/time."));
        }
        for (String query : List.of("fromTime=09:00", "fromDate=2026-10-15", "toDate=2026-10-15",
                "year=2026&month=10&fromDate=2026-10-01&toDate=2026-10-15",
                "fromDate=2026-02-30&toDate=2026-03-01", "fromDate=2026-10-15&toDate=2026-10-15&toTime=25:00",
                "fromDate=1899-12-31&toDate=2026-10-15", "fromDate=2026-10-15&toDate=9999-01-01")) {
            mvc.perform(get("/api/reports/incidents/monthly?" + query)).andExpect(status().isBadRequest());
        }
    }

    @ParameterizedTest @EnumSource(AppUserRole.class)
    void rangeReportsKeepExistingRoleRestrictions(AppUserRole role) throws Exception {
        actor(role, "owner@pareidolia.in");
        mvc.perform(get("/api/reports/incidents/monthly?fromDate=2026-10-15&toDate=2026-10-15"))
                .andExpect(status().is(role == AppUserRole.ADMIN || role == AppUserRole.IT_HANDLER ? 200 : 403));
    }

    @Test void longDescriptionsArePreservedWithoutWorkbookFailure() throws Exception {
        var incident = incident("LONG", "2026-10-01T00:00:00");
        incident.setDescription("x".repeat(40000)); incidents.saveAndFlush(incident);
        try (var workbook = new XSSFWorkbook(new ByteArrayInputStream(reportService.monthly(2026, 10)))) {
            var sheet = workbook.getSheet("Long Text");
            assertThat(sheet.getLastRowNum()).isEqualTo(2);
            assertThat(sheet.getRow(1).getCell(3).getStringCellValue() + sheet.getRow(2).getCell(3).getStringCellValue())
                    .isEqualTo(incident.getDescription());
        }
    }

    @Test void pngAndJpegPersistWithSessionActorExactlyOneAuditEachAndSafeDownloads() throws Exception {
        var incident = incident("IMAGES", "2026-10-01T00:00:00");
        var png = image("png"); var jpeg = image("jpeg");
        mvc.perform(multipart("/api/incidents/{id}/attachments", incident.getId()).file(png).file(jpeg)
                        .param("uploadedBy", "spoofed@pareidolia.in")).andExpect(status().isCreated());
        entityManager.flush(); entityManager.clear();
        var metadata = attachmentService.list(incident.getId());
        assertThat(metadata).hasSize(2);
        assertThat(metadata).allSatisfy(item -> {
            assertThat(item.uploadedBy()).isEqualTo("owner@pareidolia.in");
            assertThat(item.originalFilename()).doesNotContain("/", "\\", "\r", "\n", ".html");
            assertThat(item.uploadedAt()).isNotNull();
        });
        assertThat(history.findByIncidentIdOrderByChangedAtDesc(incident.getId())).hasSize(2)
                .allSatisfy(event -> {
                    assertThat(event.getActionType()).isEqualTo(HistoryActionType.ATTACHMENT_ADDED);
                    assertThat(event.getChangedBy()).isEqualTo("owner@pareidolia.in");
                });
        mvc.perform(get("/api/incidents/{id}/attachments/{attachment}", incident.getId(), metadata.get(0).id()))
                .andExpect(status().isOk()).andExpect(content().contentType("image/png"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(content().bytes(png.getBytes()));
        assertThat(attachmentService.content(incident.getId(), metadata.get(1).id()).data()).isEqualTo(jpeg.getBytes());
        assertThat(incidents.findById(incident.getId()).orElseThrow().getStatus()).isEqualTo(IncidentStatus.ASSIGNED);
    }

    @ParameterizedTest @EnumSource(AppUserRole.class)
    void attachmentRoleMatrix(AppUserRole role) throws Exception {
        var incident = incident("ROLES", "2026-10-01T00:00:00");
        var saved = attachmentService.upload(incident.getId(), List.of(image("png"))).get(0);
        actor(role, "owner@pareidolia.in");
        mvc.perform(get("/api/incidents/{id}/attachments", incident.getId())).andExpect(status().isOk());
        mvc.perform(get("/api/incidents/{id}/attachments/{a}", incident.getId(), saved.id())).andExpect(status().isOk());
        mvc.perform(multipart("/api/incidents/{id}/attachments", incident.getId()).file(image("png")))
                .andExpect(status().is(role == AppUserRole.REVIEWER ? 403 : 201));
    }

    @Test void ownershipAndAttachmentIncidentPairCannotBeBypassed() throws Exception {
        var own = incident("OWN", "2026-10-01T00:00:00");
        var other = incident("OTHER", "2026-10-01T00:00:00");
        other.setReportedBy("other@pareidolia.in"); incidents.saveAndFlush(other);
        var saved = attachmentService.upload(other.getId(), List.of(image("png"))).get(0);
        actor(AppUserRole.REPORTER, "owner@pareidolia.in");
        mvc.perform(get("/api/incidents/{id}/attachments", other.getId())).andExpect(status().isForbidden());
        mvc.perform(multipart("/api/incidents/{id}/attachments", other.getId()).file(image("png"))).andExpect(status().isForbidden());
        mvc.perform(get("/api/incidents/{id}/attachments/{a}", other.getId(), saved.id())).andExpect(status().isForbidden());
        mvc.perform(get("/api/incidents/{id}/attachments/{a}", own.getId(), saved.id())).andExpect(status().isNotFound());
        mvc.perform(get("/api/incidents/999999/attachments")).andExpect(status().isNotFound());
    }

    @Test void invalidBatchIsRejectedWithoutPartialAttachmentOrAuditWrites() throws Exception {
        var incident = incident("INVALID", "2026-10-01T00:00:00");
        for (var invalid : List.of(
                new MockMultipartFile("files", "fake.png", "image/png", "<script>bad</script>".getBytes()),
                new MockMultipartFile("files", "empty.png", "image/png", new byte[0]),
                new MockMultipartFile("files", "large.png", "image/png", new byte[5 * 1024 * 1024 + 1]),
                new MockMultipartFile("files", "broken.png", "image/png", Arrays.copyOf(image("png").getBytes(), 32)),
                image("gif"))) {
            mvc.perform(multipart("/api/incidents/{id}/attachments", incident.getId()).file(image("png")).file(invalid))
                    .andExpect(status().isBadRequest());
        }
        var request = multipart("/api/incidents/{id}/attachments", incident.getId());
        for (int n = 0; n < 6; n++) request.file(image("png"));
        mvc.perform(request).andExpect(status().isBadRequest());
        mvc.perform(multipart("/api/incidents/{id}/attachments", incident.getId())).andExpect(status().isBadRequest());
        assertThat(attachments.count()).isZero(); assertThat(history.count()).isZero();
        assertThat(incidents.existsById(incident.getId())).isTrue();
    }

    @Test void metadataIncidentReadsAndReportsNeverSelectBlobColumn() throws Exception {
        var incident = incident("METADATA", "2026-10-01T00:00:00");
        attachmentService.upload(incident.getId(), List.of(image("png")));
        entityManager.flush(); entityManager.clear(); SqlCapture.statements.clear();
        attachmentService.list(incident.getId()); incidentService.getAllIncidents(); reportService.monthly(2026, 10);
        assertThat(SqlCapture.statements).noneMatch(sql -> sql.toLowerCase(Locale.ROOT).contains("file_data"));
    }
}
