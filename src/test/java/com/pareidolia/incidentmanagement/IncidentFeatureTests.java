package com.pareidolia.incidentmanagement;

import com.pareidolia.incidentmanagement.controller.*;
import com.pareidolia.incidentmanagement.entity.*;
import com.pareidolia.incidentmanagement.enums.*;
import com.pareidolia.incidentmanagement.exception.*;
import com.pareidolia.incidentmanagement.mapper.IncidentMapper;
import com.pareidolia.incidentmanagement.repository.*;
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
@Import({IncidentServiceImpl.class, IncidentMapper.class, IncidentAttachmentServiceImpl.class, IncidentReportServiceImpl.class})
class IncidentFeatureTests {
    @Autowired IncidentRepository incidents;
    @Autowired IncidentHistoryRepository history;
    @Autowired IncidentAttachmentRepository attachments;
    @Autowired IncidentAttachmentService attachmentService;
    @Autowired IncidentReportService reportService;
    @Autowired IncidentService incidentService;
    @Autowired AppUserRepository appUsers;
    @Autowired EntityManager entityManager;
    @MockitoBean AppUserService users;
    MockMvc mvc;

    public static class SqlCapture implements StatementInspector {
        static final List<String> statements = new ArrayList<>();
        @Override public String inspect(String sql) { statements.add(sql); return sql; }
    }

    @BeforeEach void setup() {
        actor(AppUserRole.ADMIN, "owner@pareidolia.in");
        mvc = MockMvcBuilders.standaloneSetup(new IncidentAttachmentController(attachmentService),
                new IncidentReportController(reportService)).setControllerAdvice(new GlobalExceptionHandler()).build();
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

    MockMultipartFile image(String format) throws IOException {
        var bytes = new ByteArrayOutputStream();
        ImageIO.write(new BufferedImage(3, 3, BufferedImage.TYPE_INT_RGB), format, bytes);
        // Filename and claimed MIME must not control detected type.
        return new MockMultipartFile("files", "../../error\r\n.html", "text/html", bytes.toByteArray());
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
