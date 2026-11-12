package com.pareidolia.incidentmanagement;

import com.pareidolia.incidentmanagement.entity.*;
import com.pareidolia.incidentmanagement.enums.*;
import com.pareidolia.incidentmanagement.mapper.IncidentMapper;
import com.pareidolia.incidentmanagement.repository.*;
import com.pareidolia.incidentmanagement.security.*;
import com.pareidolia.incidentmanagement.service.*;
import com.pareidolia.incidentmanagement.service.impl.*;
import jakarta.persistence.EntityManager;
import java.io.ByteArrayInputStream;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Supplier;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.*;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.FileSystemResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.annotation.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Runs on isolated H2 by default, or only the explicitly approved Docker MySQL schema. */
@DataJpaTest(properties={"app.incident-access.enabled=true","app.incident-security-admin.enabled=true","app.notifications.email.recipient-administration.enabled=true","app.employee-management.enabled=true","app.employee-management.allowed-emails=admin@example.test","app.auth.allowed-domain=example.test","app.auth.bootstrap-admin-emails=","app.auth.bootstrap-it-handler-emails=","app.default-it-owner=owner@example.test"})
@AutoConfigureTestDatabase(replace=AutoConfigureTestDatabase.Replace.NONE)
@ActiveProfiles("dev")
@Import({IncidentSecurityGate.class,IncidentReadSnapshot.class,IncidentAccessPolicy.class,AppUserService.class,EmployeeManagementAccess.class,EmployeeDirectoryService.class,IncidentSecurityAdministrationService.class,IncidentServiceImpl.class,IncidentMapper.class,IncidentAttachmentServiceImpl.class,IncidentReportServiceImpl.class,DepartmentRecipientAdministrationService.class,WorkLogServiceImpl.class})
@Transactional(propagation=Propagation.NOT_SUPPORTED)
class IncidentSecurityLockCoordinationTests {
    @DynamicPropertySource static void database(DynamicPropertyRegistry registry){
        DisposableAssignmentDatabase.configure(registry, "incident_security_coordination");
    }
    @Autowired JdbcTemplate db;@Autowired javax.sql.DataSource source;@Autowired AppUserRepository users;@Autowired IncidentRepository incidents;
    @Autowired IncidentService incidentService;@Autowired IncidentAttachmentService attachments;@Autowired IncidentReportService reports;
    @Autowired IncidentSecurityAdministrationService administration;@Autowired EmployeeDirectoryService employees;@Autowired IncidentSecurityGate gate;
    @Autowired DepartmentRecipientAdministrationService recipients;
    @Autowired WorkLogService workLogs;
    @Autowired org.springframework.transaction.PlatformTransactionManager transactionManager;
    @MockitoSpyBean IncidentReadSnapshot snapshot;
    @Autowired IncidentHistoryRepository historyRepository;@Autowired IncidentAttachmentRepository attachmentRepository;
    AppUser admin,reader;Incident incident;Long attachmentId;
    @BeforeEach void setup(){
        reset(snapshot);
        try{db.queryForObject("select count(*) from incident_security_lock",Long.class);}catch(org.springframework.dao.DataAccessException missing){
            for(String script:List.of("incident-security-administration.REVIEW-ONLY.sql","incident-security-lock.REVIEW-ONLY.sql","employee-directory.REVIEW-ONLY.sql")){
                var resource=new FileSystemResource(Path.of("docs","assignment",script));
                if(script.equals("employee-directory.REVIEW-ONLY.sql") && !DisposableAssignmentDatabase.mysql()){
                    db.execute("alter table app_users add column employee_id varchar(64) unique");db.execute("alter table app_users add column account_version bigint not null default 0");
                    try{String sql=java.nio.file.Files.readString(resource.getFile().toPath());new ResourceDatabasePopulator(new org.springframework.core.io.ByteArrayResource(sql.substring(sql.indexOf("CREATE TABLE")).getBytes(java.nio.charset.StandardCharsets.UTF_8))).execute(source);}catch(java.io.IOException ex){throw new IllegalStateException(ex);}
                }else new ResourceDatabasePopulator(resource).execute(source);
            }
        }
        for(String table:List.of("incident_security_grant_audit","incident_classification_audit","assignment_admin_capability_audit","incident_security_grants","incident_security_classification","assignment_admin_capabilities","employee_management_audit","incident_attachments","incident_history","work_log_entries","incidents","app_users"))db.update("delete from "+table);
        admin=account("admin@example.test",AppUserRole.ADMIN);reader=account("reader@example.test",AppUserRole.IT_HANDLER);
        incident=new Incident();incident.setIncidentNumber("INC-TEST-"+UUID.randomUUID());incident.setReportedBy("reporter@example.test");incident.setTitle("Protected synthetic");incident.setDescription("Synthetic only");incident.setIssueType(IssueType.IT_ISSUE);incident.setSeverity(Severity.LOW);incident.setPriority(Priority.LOW);incident.setReportedAt(java.time.LocalDateTime.of(2026,10,1,12,0));incident=incidents.saveAndFlush(incident);
        db.update("insert into assignment_admin_capabilities(user_id,capability,active,version) values (?,'CASE_ACCESS_ADMIN',1,0),(?,'INCIDENT_CLASSIFIER',1,0),(?,'RESTRICTED_DOWNGRADE',1,0)",admin.getId(),admin.getId(),admin.getId());
        var history=new IncidentHistory();history.setIncident(incident);history.setActionType(HistoryActionType.WORK_NOTE);history.setChangedBy(reader.getEmail());history.setRemarks("Protected synthetic history");historyRepository.saveAndFlush(history);
        var attachment=new IncidentAttachment();attachment.setIncident(incident);attachment.setOriginalFilename("synthetic.png");attachment.setContentType("image/png");attachment.setFileData(new byte[]{1,2,3});attachment.setFileSize(3);attachment.setUploadedBy(reader.getEmail());attachment.setUploadedAt(java.time.LocalDateTime.now());attachmentId=attachmentRepository.saveAndFlush(attachment).getId();
        login(admin);administration.classify(incident.getId(),"RESTRICTED",0L,"Synthetic classification");
        for(String permission:List.of("VIEW","REPORT","MODIFY","HANDLE"))administration.setGrant(incident.getId(),reader.getId(),permission,true,0L,"Synthetic grant");
        login(reader);
    }
    AppUser account(String email,AppUserRole role){var u=new AppUser();u.setEmail(email);u.setDisplayName("Synthetic");u.setRole(role);return users.saveAndFlush(u);}
    static void login(AppUser user){var oidc=mock(OidcUser.class);when(oidc.getEmail()).thenReturn(user.getEmail());when(oidc.getEmailVerified()).thenReturn(true);SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(oidc,"",List.of()));}
    @AfterEach void cleanup(){SecurityContextHolder.clearContext();reset(snapshot);}
    <T>T as(AppUser user,Callable<T> action)throws Exception{login(user);try{return action.call();}finally{SecurityContextHolder.clearContext();}}
    static void await(CountDownLatch latch){try{if(!latch.await(10,TimeUnit.SECONDS))throw new IllegalStateException("Test latch timed out");}catch(InterruptedException ex){Thread.currentThread().interrupt();throw new IllegalStateException(ex);}}
    @Test void workLogOperationsWaitForCommittedDeactivationAndThenDeny() throws Exception {
        var changed=new CountDownLatch(1); var release=new CountDownLatch(1); var started=new CountDownLatch(2);
        var pool=Executors.newFixedThreadPool(3);
        try {
            var deactivate=pool.submit(()->as(admin,()->{
                new org.springframework.transaction.support.TransactionTemplate(transactionManager).executeWithoutResult(status->{
                    employees.status(reader.getId(),false,0L,"Synthetic deactivation"); changed.countDown(); await(release);
                }); return null;
            }));
            await(changed);
            var read=pool.submit(()->as(reader,()->{started.countDown();return workLogs.listOwnEntries();}));
            var write=pool.submit(()->as(reader,()->{started.countDown();var request=new com.pareidolia.incidentmanagement.dto.CreateWorkLogRequestDto();request.setWorkedAt(java.time.LocalDateTime.of(2026,1,1,0,0));request.setCategory("OTHER");request.setSummary("Synthetic");return workLogs.createOwnEntry(request);}));
            await(started);
            assertThatThrownBy(()->read.get(250,TimeUnit.MILLISECONDS)).isInstanceOf(TimeoutException.class);
            assertThatThrownBy(()->write.get(250,TimeUnit.MILLISECONDS)).isInstanceOf(TimeoutException.class);
            release.countDown(); deactivate.get(10,TimeUnit.SECONDS);
            assertThatThrownBy(()->read.get(10,TimeUnit.SECONDS)).hasCauseInstanceOf(org.springframework.security.access.AccessDeniedException.class);
            assertThatThrownBy(()->write.get(10,TimeUnit.SECONDS)).hasCauseInstanceOf(org.springframework.security.access.AccessDeniedException.class);
            assertThat(db.queryForObject("select count(*) from work_log_entries",Long.class)).isZero();
        } finally { release.countDown(); pool.shutdownNow(); }
    }
    @Test void readLinearizesBeforeRevocationAndLaterReadsDeny()throws Exception{
        var pool=Executors.newFixedThreadPool(2);var copied=new CountDownLatch(1);var release=new CountDownLatch(1);var started=new CountDownLatch(1);
        try{
            var read=pool.submit(()->as(reader,()->snapshot.read(()->{var dto=incidentService.getIncident(incident.getId());copied.countDown();await(release);return dto;})));
            await(copied);
            var revoke=pool.submit(()->as(admin,()->{started.countDown();return administration.setGrant(incident.getId(),reader.getId(),"VIEW",false,1L,"Concurrent revoke");}));
            await(started);assertThatThrownBy(()->revoke.get(250,TimeUnit.MILLISECONDS)).isInstanceOf(TimeoutException.class);
            release.countDown();assertThat(read.get(10,TimeUnit.SECONDS).getId()).isEqualTo(incident.getId());assertThat(revoke.get(10,TimeUnit.SECONDS)).isEqualTo(2L);
            login(reader);assertThatThrownBy(()->incidentService.getIncidentHistory(incident.getId())).isInstanceOfAny(com.pareidolia.incidentmanagement.exception.IncidentNotFoundException.class,org.springframework.security.access.AccessDeniedException.class);assertThatThrownBy(()->attachments.list(incident.getId())).isInstanceOfAny(com.pareidolia.incidentmanagement.exception.IncidentNotFoundException.class,org.springframework.security.access.AccessDeniedException.class);assertThatThrownBy(()->incidentService.getIncident(incident.getId())).isInstanceOf(com.pareidolia.incidentmanagement.exception.IncidentNotFoundException.class);
            assertThatThrownBy(()->attachments.content(incident.getId(),attachmentId)).isInstanceOf(com.pareidolia.incidentmanagement.exception.IncidentNotFoundException.class);
        }finally{release.countDown();pool.shutdownNow();}
    }
    @Test void reportReleasesGateBeforeRenderingAndUsesAuthorizedSnapshot()throws Exception{
        var copied=new CountDownLatch(1);var render=new CountDownLatch(1);var pool=Executors.newSingleThreadExecutor();
        doAnswer(inv->{Object result=inv.callRealMethod();if(Thread.currentThread().getName().equals("report-render")){assertThat(gate.held()).isFalse();copied.countDown();await(render);}return result;}).when(snapshot).read(org.mockito.ArgumentMatchers.any());
        try{
            var report=pool.submit(()->{Thread.currentThread().setName("report-render");return as(reader,()->reports.monthly(2026,10));});await(copied);
            login(admin);assertThat(administration.setGrant(incident.getId(),reader.getId(),"VIEW",false,1L,"Revoke after report snapshot")).isEqualTo(2L);
            render.countDown();try(var book=new XSSFWorkbook(new ByteArrayInputStream(report.get(10,TimeUnit.SECONDS)))){assertThat(book.getSheet("Incidents").getPhysicalNumberOfRows()).isEqualTo(2);assertThat(book.getSheet("Lifecycle History").getPhysicalNumberOfRows()).isEqualTo(2);}
            reset(snapshot);login(reader);try(var book=new XSSFWorkbook(new ByteArrayInputStream(reports.monthly(2026,10)))){assertThat(book.getSheet("Incidents").getPhysicalNumberOfRows()).isEqualTo(1);assertThat(book.getSheet("Lifecycle History").getPhysicalNumberOfRows()).isEqualTo(1);}
        }finally{render.countDown();pool.shutdownNow();}
    }
    @Test void classificationAndDeactivationWritersWaitForReaders()throws Exception{
        login(admin);administration.classify(incident.getId(),"STANDARD",1L,"Synthetic standard");administration.setGrant(incident.getId(),reader.getId(),"VIEW",false,1L,"Reporter only");
        db.update("update incidents set reported_by=? where id=?",reader.getEmail(),incident.getId());
        for(boolean deactivate:List.of(false,true)){
            var copied=new CountDownLatch(1);var release=new CountDownLatch(1);var started=new CountDownLatch(1);var pool=Executors.newFixedThreadPool(2);
            try{
                var read=pool.submit(()->as(reader,()->snapshot.read(()->{var dto=incidentService.getIncident(incident.getId());copied.countDown();await(release);return dto;})));await(copied);
                var writer=pool.submit(()->as(admin,()->{started.countDown();return deactivate?employees.status(reader.getId(),false,0L,"Synthetic deactivation"):administration.classify(incident.getId(),"RESTRICTED",2L,"Concurrent classification");}));
                await(started);assertThatThrownBy(()->writer.get(250,TimeUnit.MILLISECONDS)).isInstanceOf(TimeoutException.class);release.countDown();read.get(10,TimeUnit.SECONDS);writer.get(10,TimeUnit.SECONDS);
                login(reader);assertThatThrownBy(()->incidentService.getIncidentHistory(incident.getId())).isInstanceOfAny(com.pareidolia.incidentmanagement.exception.IncidentNotFoundException.class,org.springframework.security.access.AccessDeniedException.class);assertThatThrownBy(()->attachments.list(incident.getId())).isInstanceOfAny(com.pareidolia.incidentmanagement.exception.IncidentNotFoundException.class,org.springframework.security.access.AccessDeniedException.class);assertThatThrownBy(()->incidentService.getIncident(incident.getId())).isInstanceOfAny(com.pareidolia.incidentmanagement.exception.IncidentNotFoundException.class,org.springframework.security.access.AccessDeniedException.class);
                if(!deactivate){login(admin);administration.classify(incident.getId(),"STANDARD",3L,"Reset for deactivation");}
            }finally{release.countDown();pool.shutdownNow();}
        }
    }
    @Test void invalidClassificationCannotReachDetailListsAttachmentsOrEitherReportSheet() throws Exception {
        db.update("update incident_security_classification set classification='STANDARD',version=0 where incident_id=?",
                incident.getId());
        assertThatThrownBy(() -> incidentService.getIncident(incident.getId()))
                .isInstanceOf(com.pareidolia.incidentmanagement.exception.IncidentNotFoundException.class);
        assertThatThrownBy(() -> incidentService.getIncidentByNumber(incident.getIncidentNumber()))
                .isInstanceOf(com.pareidolia.incidentmanagement.exception.IncidentNotFoundException.class);
        assertThat(incidentService.getAllIncidents()).isEmpty();
        assertThat(incidentService.getIncidentsPage(0, 10)).isEmpty();
        assertThatThrownBy(() -> attachments.content(incident.getId(), attachmentId))
                .isInstanceOf(com.pareidolia.incidentmanagement.exception.IncidentNotFoundException.class);
        try (var book = new XSSFWorkbook(new ByteArrayInputStream(reports.monthly(2026, 10)))) {
            assertThat(book.getSheet("Incidents").getPhysicalNumberOfRows()).isEqualTo(1);
            assertThat(book.getSheet("Lifecycle History").getPhysicalNumberOfRows()).isEqualTo(1);
        }
    }

    @Test void routingSnapshotWaitsForRecipientDeactivationCommit() throws Exception {
        db.execute("create table if not exists employee_mapping_admins(user_id bigint primary key,active boolean)");
        db.execute("create table if not exists employee_departments(id bigint primary key,display_name varchar(150),active boolean)");
        db.execute("""
                create table if not exists incident_department_mail_recipient (
                    id char(36) primary key, department_id bigint, email varchar(254), active boolean, version bigint
                )
                """);
        db.execute("""
                create table if not exists incident_department_mail_recipient_audit (
                    recipient_id char(36), actor_user_id bigint, old_email varchar(254), new_email varchar(254),
                    old_active boolean, new_active boolean, version bigint, reason varchar(500),
                    changed_at timestamp default current_timestamp, primary key(recipient_id,version)
                )
                """);
        db.update("insert into employee_mapping_admins values(?,true)", admin.getId());
        db.update("insert into employee_departments values(7,'IT',true)");
        String email = "team@example.test";
        login(admin);
        var id = recipients.add(7, email, "Synthetic recipient");
        Supplier<Integer> active = () -> db.queryForObject("""
                select count(*) from incident_department_mail_recipient where department_id=? and email=? and active=true
                """, Integer.class, 7L, email);
        assertThat(snapshot.read(active)).isEqualTo(1);
        assertThatThrownBy(() -> snapshot.read(() -> {
            recipients.update(id, email, false, 0, "Invalid lock upgrade");
            return null;
        })).isInstanceOf(IllegalStateException.class).hasMessage("Security read-to-write lock upgrades are forbidden.");

        var changed = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var reading = new CountDownLatch(1);
        var pool = Executors.newFixedThreadPool(2);
        try {
            var writer = pool.submit(() -> as(admin, () -> {
                new org.springframework.transaction.support.TransactionTemplate(transactionManager).executeWithoutResult(status -> {
                    recipients.update(id, email, false, 0, "Synthetic deactivation");
                    changed.countDown();
                    await(release);
                });
                return null;
            }));
            await(changed);
            var read = pool.submit(() -> {
                reading.countDown();
                return snapshot.read(active);
            });
            await(reading);
            assertThatThrownBy(() -> read.get(250, TimeUnit.MILLISECONDS)).isInstanceOf(TimeoutException.class);
            release.countDown();
            writer.get(10, TimeUnit.SECONDS);
            assertThat(read.get(10, TimeUnit.SECONDS)).isZero();
            assertThat(recipients.history(id)).extracting(DepartmentRecipientAdministrationService.Audit::reason)
                    .containsExactly("Synthetic deactivation", "Synthetic recipient");
        } finally {
            release.countDown();
            pool.shutdownNow();
        }
    }

    @Test void viewOnlyMonitorPermissionsCannotMutate(){
        login(admin);administration.setGrant(incident.getId(),reader.getId(),"HANDLE",false,1L,"View only monitor");administration.setGrant(incident.getId(),reader.getId(),"MODIFY",false,1L,"View only monitor");login(reader);
        assertThat(incidentService.getIncident(incident.getId()).getId()).isEqualTo(incident.getId());
        assertThatThrownBy(()->incidentService.updateInvestigation(incident.getId(),new com.pareidolia.incidentmanagement.dto.UpdateInvestigationRequestDto())).isInstanceOf(com.pareidolia.incidentmanagement.exception.IncidentNotFoundException.class);
    }
    @Test void unauthorizedListsReportsAndMonitorWritesAreDenied()throws Exception{
        login(admin);administration.setGrant(incident.getId(),reader.getId(),"VIEW",false,1L,"Synthetic revoke");login(reader);
        assertThat(incidentService.getAllIncidents()).isEmpty();
        assertThatThrownBy(()->incidentService.assignIncident(incident.getId(),new com.pareidolia.incidentmanagement.dto.AssignIncidentRequestDto())).isInstanceOf(com.pareidolia.incidentmanagement.exception.IncidentNotFoundException.class);
        db.update("update app_users set role='REVIEWER' where id=?",reader.getId());
        var request=new com.pareidolia.incidentmanagement.dto.UpdateInvestigationRequestDto();
        assertThatThrownBy(()->incidentService.updateInvestigation(incident.getId(),request)).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
    }
}
