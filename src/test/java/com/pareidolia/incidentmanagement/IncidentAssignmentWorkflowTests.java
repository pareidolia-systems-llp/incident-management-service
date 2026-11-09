package com.pareidolia.incidentmanagement;

import com.pareidolia.incidentmanagement.controller.DepartmentMembershipAdminController;
import com.pareidolia.incidentmanagement.dto.*;
import com.pareidolia.incidentmanagement.entity.*;
import com.pareidolia.incidentmanagement.enums.*;
import com.pareidolia.incidentmanagement.exception.GlobalExceptionHandler;
import com.pareidolia.incidentmanagement.mapper.IncidentMapper;
import com.pareidolia.incidentmanagement.repository.*;
import com.pareidolia.incidentmanagement.security.*;
import com.pareidolia.incidentmanagement.service.*;
import com.pareidolia.incidentmanagement.service.impl.*;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.*;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.FileSystemResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.*;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.server.ResponseStatusException;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Real persistence/policy/gate with synthetic OIDC identities. Activation guard is deliberately not in this isolated slice. */
@DataJpaTest(properties={"spring.datasource.url=jdbc:h2:mem:functional_assignment;MODE=MySQL;DB_CLOSE_DELAY=-1","spring.datasource.username=sa","spring.datasource.password=","spring.jpa.hibernate.ddl-auto=create-drop","app.incident-access.enabled=true","app.incident-assignment.enabled=true","app.incident-transfer.handoff-approved=true","app.department-membership-admin.enabled=true","app.department-membership-admin.allowed-emails=membership@example.test","app.employee-management.enabled=true","app.incident-security-admin.enabled=true","app.auth.allowed-domain=example.test","app.auth.bootstrap-admin-emails=","app.auth.bootstrap-it-handler-emails=","app.default-it-owner=legacy@example.test","app.incident-capability-admin.allowed-emails=classifier@example.test","app.incident-capability-admin.global-view-approver-emails=classifier@example.test"})
@AutoConfigureTestDatabase(replace=AutoConfigureTestDatabase.Replace.NONE)
@ActiveProfiles("dev")
@Import({IncidentSecurityGate.class,IncidentReadSnapshot.class,IncidentAccessPolicy.class,AppUserService.class,IncidentSecurityAdministrationService.class,IncidentServiceImpl.class,IncidentMapper.class,EligibleHandlerDirectory.class,IncidentAssignmentService.class, DepartmentMembershipAdminService.class, IncidentCapabilityAdministrationService.class, IncidentReportServiceImpl.class, com.pareidolia.incidentmanagement.service.impl.IncidentAttachmentServiceImpl.class})
@Transactional(propagation=Propagation.NOT_SUPPORTED)
class IncidentAssignmentWorkflowTests {
    @org.springframework.test.context.DynamicPropertySource
    static void database(org.springframework.test.context.DynamicPropertyRegistry registry) {
        DisposableAssignmentDatabase.configure(registry, "functional_assignment");
    }
    @Autowired JdbcTemplate db;@Autowired javax.sql.DataSource source;@Autowired AppUserRepository users;@Autowired IncidentRepository incidents;
    @Autowired IncidentService incidentService;@Autowired IncidentAssignmentService assignments;@Autowired IncidentSecurityAdministrationService administration;
    @Autowired IncidentSecurityGate gate;@Autowired IncidentReadSnapshot snapshot;@Autowired IncidentHistoryRepository history;
    @Autowired org.springframework.transaction.PlatformTransactionManager transactionManager;
    @Autowired com.pareidolia.incidentmanagement.service.IncidentAttachmentService attachments;
    @Autowired IncidentCapabilityAdministrationService capabilityAdmin;
    @Autowired IncidentReportService reports;
    @Autowired DepartmentMembershipAdminService memberships;
    AppUser reporter,assigner,handler,alternate,classifier,membershipAdmin;Incident incident;
    @BeforeEach void setup(){
        try{db.queryForObject("select count(*) from incident_assignment_state",Long.class);}catch(org.springframework.dao.DataAccessException missing){
            if (DisposableAssignmentDatabase.mysql()) {
                for (String file : List.of("employee-directory", "department-head-designations")) {
                    new ResourceDatabasePopulator(new FileSystemResource(Path.of("docs", "assignment", file + ".REVIEW-ONLY.sql"))).execute(source);
                }
            } else {
                db.execute("alter table app_users add column employee_id varchar(64) unique");
                db.execute("create table employee_departments (id bigint primary key, display_name varchar(150) not null unique, active tinyint not null)");
            }
            for(String script:List.of("handler-eligibility.REVIEW-ONLY.sql","incident-security-administration.REVIEW-ONLY.sql","incident-security-lock.REVIEW-ONLY.sql","assignment-schema.REVIEW-ONLY.sql","department-membership.REVIEW-ONLY.sql","department-membership-administration.REVIEW-ONLY.sql","incident-department-transfer.REVIEW-ONLY.sql"))new ResourceDatabasePopulator(new FileSystemResource(Path.of("docs","assignment",script))).execute(source);
        }
        for(String table:List.of("incident_department_transfer_audit","incident_global_view_audit","incident_attachments","incident_assignment_audit","incident_assignment_state","incident_security_grant_audit","incident_classification_audit","assignment_admin_capability_audit","handler_eligibility_audit","incident_security_grants","incident_security_classification","assignment_admin_capabilities","handler_eligibility_grants","incident_history","work_log_entries","incidents","employee_department_membership_audit","employee_department_memberships","employee_departments","app_users"))db.update("delete from "+table);
        reporter=account("reporter@example.test",AppUserRole.REPORTER);assigner=account("assigner@example.test",AppUserRole.ADMIN);handler=account("handler@example.test",AppUserRole.IT_HANDLER);alternate=account("alternate@example.test",AppUserRole.IT_HANDLER);classifier=account("classifier@example.test",AppUserRole.REPORTER);
        membershipAdmin = account("membership@example.test", AppUserRole.REPORTER);
        db.update("insert into employee_departments(id,display_name,active) values (71,'IT',1),(72,'Human Resources',1)");
        for (var user : List.of(handler, alternate)) {
            db.update("insert into handler_eligibility_grants(user_id,active,version) values (?,1,0)", user.getId());
            db.update("insert into employee_department_memberships(department_id,user_id,active) values (71,?,1)", user.getId());
        }
        db.update("insert into assignment_admin_capabilities(user_id,capability,active,version) values (?,'ASSIGNMENT_ADMIN',1,0),(?,'INCIDENT_CLASSIFIER',1,0),(?,'CASE_ACCESS_ADMIN',1,0)",assigner.getId(),classifier.getId(),classifier.getId());
        org.springframework.test.util.ReflectionTestUtils.setField(assignments,"allowedPairs",Set.of(assigner.getId()+":"+handler.getId(),assigner.getId()+":"+alternate.getId()));
        login(reporter);var created=incidentService.createIncident(request(handler.getId()));incident=incidents.findById(created.getId()).orElseThrow();
    }
    AppUser account(String email,AppUserRole role){var user=new AppUser();user.setEmail(email);user.setDisplayName(email.substring(0,email.indexOf('@'))+" Employee");user.setRole(role);user=users.saveAndFlush(user);db.update("update app_users set employee_id=? where id=?","EMP-"+user.getId(),user.getId());return user;}
    static void login(AppUser user){var oidc=mock(OidcUser.class);when(oidc.getEmail()).thenReturn(user.getEmail());when(oidc.getEmailVerified()).thenReturn(true);SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(oidc,"",List.of()));}
    @AfterEach void cleanup(){SecurityContextHolder.clearContext();}
    CreateIncidentRequestDto request(Long handler){var request=new CreateIncidentRequestDto();request.setProposedHandlerUserId(handler);request.setResponsibleDepartmentId(71L);request.setTitle("Synthetic incident");request.setDescription("Synthetic description");request.setAffectedSystem("Synthetic system");request.setIssueType(IssueType.IT_ISSUE);request.setSeverity(Severity.LOW);request.setPriority(Priority.LOW);return request;}
    void grant(Long user,String permission){db.update("insert into incident_security_grants(incident_id,user_id,permission,active,version) values (?,?,?,1,1)",incident.getId(),user,permission);}
    void standard(){login(classifier);administration.classify(incident.getId(),"STANDARD",0L,"Synthetic triage");grant(assigner.getId(),"VIEW");for(var user:List.of(handler,alternate)){grant(user.getId(),"VIEW");grant(user.getId(),"HANDLE");}login(assigner);}
    void conflict(Runnable work){assertThatThrownBy(work::run).isInstanceOfSatisfying(ResponseStatusException.class,e->assertThat(e.getStatusCode().value()).isEqualTo(409));}
    @Test
    void membershipChangesAreVersionedAuditedAndIndependentOfOtherGrants() {
        login(membershipAdmin);
        long target = reporter.getId();
        assertThat(memberships.change(71L, target, true, 0L, " Approved membership ")).isEqualTo(1);
        assertThat(memberships.change(71L, target, true, 1L, "Duplicate request")).isEqualTo(1);
        conflict(() -> memberships.change(71L, target, false, 0L, "Stale request"));
        assertThat(memberships.change(71L, target, false, 1L, "Department transfer")).isEqualTo(2);
        assertThat(memberships.list(71L)).filteredOn(row -> row.userId() == target)
                .singleElement().satisfies(row -> {
                    assertThat(row.active()).isFalse();
                    assertThat(row.version()).isEqualTo(2);
                    assertThat(row.email()).isEqualTo(reporter.getEmail());
                });
        assertThat(memberships.history(71L, target)).satisfiesExactly(
                revoked -> {
                    assertThat(revoked.oldActive()).isTrue();
                    assertThat(revoked.newActive()).isFalse();
                    assertThat(revoked.reason()).isEqualTo("Department transfer");
                },
                granted -> {
                    assertThat(granted.oldActive()).isNull();
                    assertThat(granted.newActive()).isTrue();
                    assertThat(granted.actorUserId()).isEqualTo(membershipAdmin.getId());
                    assertThat(granted.departmentId()).isEqualTo(71);
                    assertThat(granted.userId()).isEqualTo(target);
                    assertThat(granted.reason()).isEqualTo("Approved membership");
                    assertThat(granted.changedAt()).isNotBlank();
                });
        assertThat(db.queryForObject("select count(*) from handler_eligibility_grants where user_id = ?",
                Long.class, target)).isZero();
        assertThat(db.queryForObject("select count(*) from incident_security_grants where user_id = ?",
                Long.class, target)).isZero();
    }

    @Test
    void membershipDeniesOrdinaryAdminsUnverifiedActorsAndSelfChanges() {
        login(assigner);
        assertThatThrownBy(() -> memberships.list(71L)).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> memberships.history(71L, handler.getId())).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> memberships.change(71L, handler.getId(), false, 0L, "Unauthorized"))
                .isInstanceOf(AccessDeniedException.class);
        var unverified = mock(OidcUser.class);
        when(unverified.getEmail()).thenReturn(membershipAdmin.getEmail());
        when(unverified.getEmailVerified()).thenReturn(false);
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(unverified, "", List.of()));
        assertThatThrownBy(() -> memberships.change(71L, handler.getId(), false, 0L, "Unverified"))
                .isInstanceOf(AccessDeniedException.class);
        login(membershipAdmin);
        assertThatThrownBy(() -> memberships.change(71L, membershipAdmin.getId(), true, 0L, "Self grant"))
                .isInstanceOf(AccessDeniedException.class);
        db.update("update app_users set active = false where id = ?", membershipAdmin.getId());
        assertThatThrownBy(() -> memberships.list(71L)).isInstanceOf(AccessDeniedException.class);
        assertThat(db.queryForObject("select count(*) from employee_department_membership_audit", Long.class)).isZero();
    }

    @Test
    void membershipRequiresValidTargetsVersionAndReason() {
        login(membershipAdmin);
        conflict(() -> memberships.change(72L, handler.getId(), false, 0L, "No membership"));
        assertThatThrownBy(() -> memberships.change(71L, handler.getId(), false, null, "Missing version"))
                .isInstanceOfSatisfying(ResponseStatusException.class, e -> assertThat(e.getStatusCode().value()).isEqualTo(400));
        assertThatThrownBy(() -> memberships.change(71L, handler.getId(), false, 0L, " "))
                .isInstanceOfSatisfying(ResponseStatusException.class, e -> assertThat(e.getStatusCode().value()).isEqualTo(400));
        assertThatThrownBy(() -> memberships.change(999L, handler.getId(), true, 0L, "Missing department"))
                .isInstanceOf(AccessDeniedException.class);
        db.update("update employee_departments set active = 0 where id = 72");
        assertThatThrownBy(() -> memberships.change(72L, handler.getId(), true, 0L, "Inactive department"))
                .isInstanceOf(AccessDeniedException.class);
        db.update("update app_users set active = false where id = ?", handler.getId());
        assertThatThrownBy(() -> memberships.change(71L, handler.getId(), false, 0L, "Inactive employee"))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void membershipAuditFailureRollsBackGrantAndRevocation() {
        login(membershipAdmin);
        db.execute("alter table employee_department_membership_audit add constraint reject_test_audit check (reason <> 'Reject audit')");
        try {
            assertThatThrownBy(() -> memberships.change(72L, handler.getId(), true, 0L, "Reject audit"))
                    .isInstanceOf(RuntimeException.class);
            assertThat(memberships.list(72L)).isEmpty();
            assertThatThrownBy(() -> memberships.change(71L, handler.getId(), false, 0L, "Reject audit"))
                    .isInstanceOf(RuntimeException.class);
            assertThat(memberships.list(71L)).filteredOn(row -> row.userId() == handler.getId())
                    .singleElement().satisfies(row -> {
                        assertThat(row.active()).isTrue();
                        assertThat(row.version()).isZero();
                    });
            assertThat(memberships.history(71L, handler.getId())).isEmpty();
        } finally {
            db.execute("alter table employee_department_membership_audit drop constraint reject_test_audit");
        }
    }

    @Test
    void assignmentWaitingOnMembershipRevocationRechecksMembershipBeforeWriting() throws Exception {
        standard();
        var revoked = new CountDownLatch(1);
        var commit = new CountDownLatch(1);
        var assignmentStarted = new CountDownLatch(1);
        var workers = Executors.newFixedThreadPool(2);
        try {
            var revocation = workers.submit(() -> {
                login(membershipAdmin);
                try {
                    new org.springframework.transaction.support.TransactionTemplate(transactionManager).executeWithoutResult(status -> {
                        assertThat(memberships.change(71L, handler.getId(), false, 0L, "Transfer")).isEqualTo(1);
                        assertThat(gate.held()).isTrue();
                        revoked.countDown();
                        try {
                            if (!commit.await(10, TimeUnit.SECONDS)) throw new IllegalStateException("Commit latch timed out");
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            throw new IllegalStateException(e);
                        }
                    });
                } finally {
                    SecurityContextHolder.clearContext();
                }
            });
            assertThat(revoked.await(10, TimeUnit.SECONDS)).isTrue();
            var assignment = workers.submit(() -> {
                login(assigner);
                assignmentStarted.countDown();
                try {
                    return assignments.assign(incident.getId(), handler.getId(), 0L, 1L, "Assign");
                } finally {
                    SecurityContextHolder.clearContext();
                }
            });
            assertThat(assignmentStarted.await(10, TimeUnit.SECONDS)).isTrue();
            assertThatThrownBy(() -> assignment.get(250, TimeUnit.MILLISECONDS)).isInstanceOf(TimeoutException.class);
            commit.countDown();
            revocation.get(10, TimeUnit.SECONDS);
            assertThatThrownBy(() -> assignment.get(10, TimeUnit.SECONDS)).hasCauseInstanceOf(AccessDeniedException.class);
            assertThat(assignments.get(incident.getId()).handler()).isNull();
        } finally {
            commit.countDown();
            workers.shutdownNow();
            assertThat(workers.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test
    void membershipHttpContractRequiresVersionAndReturnsAuditHistory() throws Exception {
        var mvc = MockMvcBuilders.standaloneSetup(new DepartmentMembershipAdminController(memberships))
                .setControllerAdvice(new GlobalExceptionHandler()).build();
        String department = "/api/admin/department-memberships/72";
        String target = department + "/" + handler.getId();
        login(assigner);
        mvc.perform(get(department)).andExpect(status().isForbidden());
        login(membershipAdmin);
        mvc.perform(put(target).contentType("application/json").content("""
                {"active":true,"reason":"Approved"}
                """)).andExpect(status().isBadRequest());
        mvc.perform(put(target).contentType("application/json").content("""
                {"active":true,"expectedVersion":0,"reason":"Approved"}
                """)).andExpect(status().isOk()).andExpect(jsonPath("$.version").value(1));
        mvc.perform(put(target).contentType("application/json").content("""
                {"active":false,"expectedVersion":0,"reason":"Stale"}
                """)).andExpect(status().isConflict());
        mvc.perform(get(department)).andExpect(status().isOk())
                .andExpect(jsonPath("$[0].userId").value(handler.getId()));
        mvc.perform(get(target + "/history")).andExpect(status().isOk())
                .andExpect(jsonPath("$[0].reason").value("Approved"));
    }

    @Test
    void transferDiscoveryHttpReturnsOnlyAuthorizedDestinationsAndHandlersWithVersions() throws Exception {
        prepareTransfer();
        db.update("insert into employee_departments(id,display_name,active) values (74,'Inactive',0),(75,'Unapproved',1)");
        transferRoutes(Set.of(assigner.getId() + ":71:73", assigner.getId() + ":71:74", assigner.getId() + ":71:999",
                assigner.getId() + ":71:71", assigner.getId() + ":71:72", assigner.getId() + ":75:71"));
        var mvc = MockMvcBuilders.standaloneSetup(
                new com.pareidolia.incidentmanagement.controller.IncidentAssignmentController(assignments))
                .setControllerAdvice(new GlobalExceptionHandler()).build();
        String base = "/api/incident-assignment/" + incident.getId() + "/transfer";
        mvc.perform(get(base + "/options")).andExpect(status().isOk())
                .andExpect(jsonPath("$.state.incidentId").value(incident.getId()))
                .andExpect(jsonPath("$.state.sourceDepartmentId").value(71))
                .andExpect(jsonPath("$.state.assignmentVersion").value(1))
                .andExpect(jsonPath("$.state.classificationVersion").value(1))
                .andExpect(jsonPath("$.destinations.length()").value(1))
                .andExpect(jsonPath("$.destinations[0].departmentId").value(73))
                .andExpect(jsonPath("$.destinations[0].displayName").value("Operations"));
        for (String destination : List.of("71", "72", "74", "75", "999")) {
            mvc.perform(get(base + "/handlers").param("destinationDepartmentId", destination).param("search", "alternate"))
                    .andExpect(status().isForbidden()).andExpect(jsonPath("$.handlers").doesNotExist());
        }
        mvc.perform(get(base + "/handlers").param("destinationDepartmentId", "73").param("search", "alternate"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.state.assignmentVersion").value(1))
                .andExpect(jsonPath("$.destinationDepartmentId").value(73))
                .andExpect(jsonPath("$.handlers.length()").value(1))
                .andExpect(jsonPath("$.handlers[0].id").value(alternate.getId()));
        mvc.perform(get(base + "/handlers").param("destinationDepartmentId", "73").param("search", "a"))
                .andExpect(status().isBadRequest());
        assertThat(transferAuditCount()).isZero();
    }

    @Test
    void transferDiscoveryDeniesDisabledPolicyMissingScopeAndMissingIndependentAssign() {
        prepareTransfer();
        login(handler);
        assertThatThrownBy(() -> assignments.transferOptions(incident.getId())).isInstanceOf(AccessDeniedException.class);
        login(assigner);
        transferRoutes(Set.of(assigner.getId() + ":73:71"));
        assertThatThrownBy(() -> assignments.transferOptions(incident.getId())).isInstanceOf(AccessDeniedException.class);
        transferRoutes(Set.of(assigner.getId() + ":71:71"));
        assertThatThrownBy(() -> assignments.transferOptions(incident.getId())).isInstanceOf(AccessDeniedException.class);
        transferRoutes(Set.of(assigner.getId() + ":71:73"));
        org.springframework.test.util.ReflectionTestUtils.setField(assignments, "transferHandoffApproved", false);
        try {
            assertThatThrownBy(() -> assignments.transferOptions(incident.getId())).isInstanceOf(AccessDeniedException.class);
        } finally {
            org.springframework.test.util.ReflectionTestUtils.setField(assignments, "transferHandoffApproved", true);
        }
        login(classifier);
        administration.setGrant(incident.getId(), assigner.getId(), "ASSIGN", false, 1L, "Withdraw transfer permission");
        login(assigner);
        assertThatThrownBy(() -> assignments.transferHandlers(incident.getId(), 73L, "alternate"))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void transferHandlerDiscoveryRechecksMembershipScopeEligibilityAndCaseGrants() {
        prepareTransfer();
        assertThat(assignments.transferHandlers(incident.getId(), 73L, "alternate").handlers()).hasSize(1);
        assertThat(assignments.transferHandlers(incident.getId(), 73L, "handler").handlers()).isEmpty();
        login(membershipAdmin);
        memberships.change(73L, alternate.getId(), false, 0L, "Withdraw membership");
        login(assigner);
        assertThat(assignments.transferHandlers(incident.getId(), 73L, "alternate").handlers()).isEmpty();
        login(membershipAdmin);
        memberships.change(73L, alternate.getId(), true, 1L, "Restore membership");
        login(assigner);
        var pairs = org.springframework.test.util.ReflectionTestUtils.getField(assignments, "allowedPairs");
        org.springframework.test.util.ReflectionTestUtils.setField(assignments, "allowedPairs", Set.of());
        try {
            assertThat(assignments.transferHandlers(incident.getId(), 73L, "alternate").handlers()).isEmpty();
        } finally {
            org.springframework.test.util.ReflectionTestUtils.setField(assignments, "allowedPairs", pairs);
        }
        db.update("update handler_eligibility_grants set active = 0 where user_id = ?", alternate.getId());
        assertThat(assignments.transferHandlers(incident.getId(), 73L, "alternate").handlers()).isEmpty();
        db.update("update handler_eligibility_grants set active = 1 where user_id = ?", alternate.getId());
        login(classifier);
        administration.setGrant(incident.getId(), alternate.getId(), "HANDLE", false, 1L, "Withdraw case access");
        login(assigner);
        assertThat(assignments.transferHandlers(incident.getId(), 73L, "alternate").handlers()).isEmpty();
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.EnumSource(value = IssueType.class, names = {"HR_ISSUE",
            "SUSPECTED_SECURITY_INCIDENT", "INFORMATION_SECURITY_INCIDENT", "MAJOR_CRITICAL_SECURITY_INCIDENT"})
    void transferDiscoveryProtectsConfidentialCasesUntilExplicitlyGrantedAndClassified(IssueType issueType) {
        incident = incidents.findById(createCase(issueType, 71L)).orElseThrow();
        addTransferDestination();
        grant(assigner.getId(), "ASSIGN");
        grant(alternate.getId(), "VIEW");
        grant(alternate.getId(), "HANDLE");
        login(assigner);
        assertThatThrownBy(() -> assignments.transferOptions(incident.getId()))
                .isInstanceOfSatisfying(ResponseStatusException.class, e -> assertThat(e.getStatusCode().value()).isEqualTo(404));
        assertThatThrownBy(() -> assignments.transferHandlers(incident.getId(), 73L, "alternate"))
                .isInstanceOfSatisfying(ResponseStatusException.class, e -> assertThat(e.getStatusCode().value()).isEqualTo(404));

        login(classifier);
        grant(assigner.getId(), "VIEW");
        login(assigner);
        assertThatThrownBy(() -> assignments.transferOptions(incident.getId())).isInstanceOf(AccessDeniedException.class);
        login(classifier);
        administration.classify(incident.getId(), "RESTRICTED", 0L, "Trusted intake");
        login(assigner);
        assertThat(assignments.transferOptions(incident.getId()).destinations())
                .extracting(IncidentAssignmentService.TransferDestination::departmentId).containsExactly(73L);
        assertThat(assignments.transferHandlers(incident.getId(), 73L, "alternate").handlers())
                .extracting(EligibleHandlerDirectory.Employee::id).containsExactly(alternate.getId());
    }

    @Test
    void transferDiscoverySnapshotsExposeStaleSelectionsAndWriteStillRejectsThem() {
        prepareTransfer();
        reconcileFormerHandler();
        transferRoutes(Set.of(assigner.getId() + ":71:73", assigner.getId() + ":73:71"));
        var before = assignments.transferOptions(incident.getId()).state();
        assertThat(assignments.transferHandlers(incident.getId(), 73L, "alternate").state()).isEqualTo(before);
        assignments.transfer(incident.getId(), transferRequest(71, 73, 1, 1));

        var after = assignments.transferOptions(incident.getId()).state();
        assertThat(after.sourceDepartmentId()).isEqualTo(73);
        assertThat(after.assignmentVersion()).isEqualTo(before.assignmentVersion() + 1);
        assertThat(after.classificationVersion()).isEqualTo(before.classificationVersion());
        assertThatThrownBy(() -> assignments.transferHandlers(incident.getId(), 73L, "alternate"))
                .isInstanceOf(AccessDeniedException.class);
        conflict(() -> assignments.transfer(incident.getId(), transferRequest(71, 73, before.assignmentVersion(),
                before.classificationVersion())));
    }

    @Test
    void transferUpdatesDepartmentAndHandlerAndKeepsPrivateAuditOutOfIncidentHistory() throws Exception {
        prepareTransfer();
        reconcileFormerHandler();
        var mvc = MockMvcBuilders.standaloneSetup(new com.pareidolia.incidentmanagement.controller.IncidentAssignmentController(assignments))
                .setControllerAdvice(new GlobalExceptionHandler()).build();
        String endpoint = "/api/incident-assignment/" + incident.getId() + "/transfer";
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post(endpoint)
                .contentType("application/json").content("{}")).andExpect(status().isBadRequest());
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post(endpoint)
                .contentType("application/json").content("""
                        {"expectedSourceDepartmentId":71,"destinationDepartmentId":73,"destinationHandlerUserId":%d,
                         "expectedVersion":1,"expectedClassificationVersion":1,
                         "reason":"Routing approved","handoffApprovalReference":"REVIEW-42"}
                        """.formatted(alternate.getId())))
                .andExpect(status().isOk()).andExpect(jsonPath("$.responsibleDepartmentId").value(73))
                .andExpect(jsonPath("$.handlerUserId").value(alternate.getId()))
                .andExpect(jsonPath("$.version").value(2)).andExpect(jsonPath("$.reason").doesNotExist());

        Incident saved = incidents.findById(incident.getId()).orElseThrow();
        assertThat(saved.getResponsibleDepartmentId()).isEqualTo(73);
        assertThat(saved.getAssignedOwner()).isEqualTo(alternate.getEmail());
        assertThat(saved.getReportedBy()).isEqualTo(reporter.getEmail());
        assertThat(assignments.get(incident.getId()).proposal()).isNull();
        assertThat(assignments.get(incident.getId()).handler().id()).isEqualTo(alternate.getId());
        assertThat(assignments.history(incident.getId())).hasSize(1);
        assertThat(history.findByIncidentIdOrderByChangedAtAscIdAsc(incident.getId()))
                .noneMatch(row -> "Routing approved".equals(row.getRemarks()));

        var audit = db.queryForMap("select * from incident_department_transfer_audit where incident_id = ?", incident.getId());
        assertThat(audit).containsEntry("actor_user_id", assigner.getId()).containsEntry("source_department_id", 71L)
                .containsEntry("destination_department_id", 73L).containsEntry("previous_handler_user_id", handler.getId())
                .containsEntry("new_handler_user_id", alternate.getId()).containsEntry("assignment_version", 2L)
                .containsEntry("classification_version", 1L).containsEntry("reason", "Routing approved")
                .containsEntry("handoff_approval_reference", "REVIEW-42");
        assertThat(audit.get("changed_at")).isNotNull();
    }

    @Test
    void transferDeniesUnapprovedPolicyCoordinatorDirectionMembershipAndPermissions() {
        prepareTransfer();
        reconcileFormerHandler();
        var request = transferRequest(71, 73, 1, 1);
        transferRoutes(Set.of(assigner.getId() + ":73:71"));
        assertThatThrownBy(() -> assignments.transfer(incident.getId(), request)).isInstanceOf(AccessDeniedException.class);
        transferRoutes(Set.of(assigner.getId() + ":71:73"));
        org.springframework.test.util.ReflectionTestUtils.setField(assignments, "transferHandoffApproved", false);
        try {
            assertThatThrownBy(() -> assignments.transfer(incident.getId(), request)).isInstanceOf(AccessDeniedException.class);
        } finally {
            org.springframework.test.util.ReflectionTestUtils.setField(assignments, "transferHandoffApproved", true);
        }
        login(membershipAdmin);
        memberships.change(73L, alternate.getId(), false, 0L, "Withdraw destination membership");
        login(assigner);
        assertThatThrownBy(() -> assignments.transfer(incident.getId(), request)).isInstanceOf(AccessDeniedException.class);
        login(membershipAdmin);
        memberships.change(73L, alternate.getId(), true, 1L, "Restore destination membership");
        login(classifier);
        administration.setGrant(incident.getId(), alternate.getId(), "HANDLE", false, 1L, "Withdraw case access");
        login(assigner);
        assertThatThrownBy(() -> assignments.transfer(incident.getId(), request)).isInstanceOf(AccessDeniedException.class);
        assertThat(transferAuditCount()).isZero();
    }

    @Test
    void transferRejectsStaleStateAndUnreconciledGrantsWithoutRemovingThem() {
        prepareTransfer();
        conflict(() -> assignments.transfer(incident.getId(), transferRequest(71, 73, 0, 1)));
        conflict(() -> assignments.transfer(incident.getId(), transferRequest(71, 73, 1, 0)));
        transferRoutes(Set.of(assigner.getId() + ":71:73", assigner.getId() + ":72:73"));
        conflict(() -> assignments.transfer(incident.getId(), transferRequest(72, 73, 1, 1)));
        assertThatThrownBy(() -> assignments.transfer(incident.getId(), transferRequest(71, 73, 1, 1)))
                .isInstanceOfSatisfying(ResponseStatusException.class, error ->
                        assertThat(error.getReason()).contains("independent handoff review"));
        assertThat(db.queryForObject("select count(*) from incident_security_grants where user_id=? and active=1",
                Long.class, handler.getId())).isEqualTo(2);
        reconcileFormerHandler();
        grant(classifier.getId(), "VIEW");
        conflict(() -> assignments.transfer(incident.getId(), transferRequest(71, 73, 1, 1)));
        assertThat(db.queryForObject("select count(*) from incident_security_grants where user_id=? and active=1",
                Long.class, classifier.getId())).isEqualTo(1);
        assertThat(transferAuditCount()).isZero();
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.EnumSource(value = IssueType.class, names = {"HR_ISSUE",
            "SUSPECTED_SECURITY_INCIDENT", "INFORMATION_SECURITY_INCIDENT", "MAJOR_CRITICAL_SECURITY_INCIDENT"})
    void confidentialTransferPreservesClassificationAndReporterRights(IssueType type) throws Exception {
        incident = incidents.findById(createCase(type, 71L)).orElseThrow();
        login(classifier);
        administration.classify(incident.getId(), "RESTRICTED", 0L, "Restricted intake");
        grant(reporter.getId(), "VIEW");
        grant(assigner.getId(), "VIEW");
        grant(assigner.getId(), "ASSIGN");
        grant(alternate.getId(), "VIEW");
        grant(alternate.getId(), "HANDLE");
        addTransferDestination();
        login(handler);
        assertThatThrownBy(() -> assignments.transfer(incident.getId(), transferRequest(71, 73, 0, 1)))
                .isInstanceOf(AccessDeniedException.class);
        login(assigner);
        var result = assignments.transfer(incident.getId(), transferRequest(71, 73, 0, 1));
        assertThat(result.responsibleDepartmentId()).isEqualTo(73);
        assertThat(assignments.get(incident.getId()).classification()).isEqualTo("RESTRICTED");
        assertThat(incidentService.getIncident(incident.getId()).getIssueType()).isEqualTo(type);
        login(handler);
        assertThat(incidentService.getAllIncidents()).isEmpty();
        assertThatThrownBy(() -> assignments.search("alternate", incident.getId())).isInstanceOf(ResponseStatusException.class);
        assertThatThrownBy(() -> assignments.history(incident.getId())).isInstanceOf(ResponseStatusException.class);
        assertThatThrownBy(() -> attachments.list(incident.getId())).isInstanceOf(
                com.pareidolia.incidentmanagement.exception.IncidentNotFoundException.class);
        var today = java.time.LocalDate.now();
        try (var workbook = new org.apache.poi.xssf.usermodel.XSSFWorkbook(
                new java.io.ByteArrayInputStream(reports.monthly(today.getYear(), today.getMonthValue())))) {
            assertThat(workbook.getSheet("Incidents").getPhysicalNumberOfRows()).isEqualTo(1);
        }
        login(alternate);
        var resolution = new ResolveIncidentRequestDto();
        resolution.setResolutionDetails("Synthetic resolution");
        incidentService.resolveIncident(incident.getId(), resolution);
        var validation = new ValidateIncidentRequestDto();
        validation.setValidationDetails("Synthetic validation");
        assertThatThrownBy(() -> incidentService.validateIncident(incident.getId(), validation))
                .isInstanceOf(AccessDeniedException.class);
        login(reporter);
        assertThat(incidentService.getIncident(incident.getId()).getResponsibleDepartmentId()).isEqualTo(73);
        assertThat(incidentService.validateIncident(incident.getId(), validation).getStatus()).isEqualTo(IncidentStatus.VALIDATED);
        assertThat(incidentService.closeIncident(incident.getId(), new CloseIncidentRequestDto()).getStatus())
                .isEqualTo(IncidentStatus.CLOSED);
    }

    @Test
    void transferAuditFailureRollsBackAssignmentAndResponsibleDepartment() {
        prepareTransfer();
        reconcileFormerHandler();
        db.execute("alter table incident_department_transfer_audit add constraint reject_transfer_audit check (assignment_version < 2)");
        try {
            assertThatThrownBy(() -> assignments.transfer(incident.getId(), transferRequest(71, 73, 1, 1)))
                    .isInstanceOf(RuntimeException.class);
            assertThat(transferAuditCount()).isZero();
            assertThat(assignments.get(incident.getId()).version()).isEqualTo(1);
            assertThat(assignments.get(incident.getId()).handler().id()).isEqualTo(handler.getId());
            Incident saved = incidents.findById(incident.getId()).orElseThrow();
            assertThat(saved.getResponsibleDepartmentId()).isEqualTo(71);
            assertThat(saved.getAssignedOwner()).isEqualTo(handler.getEmail());
        } finally {
            db.execute("alter table incident_department_transfer_audit drop constraint reject_transfer_audit");
        }
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(booleans = {true, false})
    void transferWaitingOnRevocationRechecksDestinationMembershipAndCaseGrant(boolean membership) throws Exception {
        prepareTransfer();
        reconcileFormerHandler();
        var revoked = new CountDownLatch(1);
        var commit = new CountDownLatch(1);
        var started = new CountDownLatch(1);
        var workers = Executors.newFixedThreadPool(2);
        try {
            var revocation = workers.submit(() -> {
                login(membershipAdmin);
                try {
                    new org.springframework.transaction.support.TransactionTemplate(transactionManager).executeWithoutResult(status -> {
                        if (membership) {
                            memberships.change(73L, alternate.getId(), false, 0L, "Remove destination access");
                        } else {
                            login(classifier);
                            administration.setGrant(incident.getId(), alternate.getId(), "HANDLE", false, 1L, "Revoke case access");
                        }
                        revoked.countDown();
                        try {
                            if (!commit.await(10, TimeUnit.SECONDS)) throw new IllegalStateException("Commit latch timed out");
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            throw new IllegalStateException(e);
                        }
                    });
                } finally {
                    SecurityContextHolder.clearContext();
                }
            });
            assertThat(revoked.await(10, TimeUnit.SECONDS)).isTrue();
            var transfer = workers.submit(() -> {
                login(assigner);
                started.countDown();
                try {
                    return assignments.transfer(incident.getId(), transferRequest(71, 73, 1, 1));
                } finally {
                    SecurityContextHolder.clearContext();
                }
            });
            assertThat(started.await(10, TimeUnit.SECONDS)).isTrue();
            assertThatThrownBy(() -> transfer.get(250, TimeUnit.MILLISECONDS)).isInstanceOf(TimeoutException.class);
            commit.countDown();
            revocation.get(10, TimeUnit.SECONDS);
            assertThatThrownBy(() -> transfer.get(10, TimeUnit.SECONDS)).hasCauseInstanceOf(AccessDeniedException.class);
            assertThat(transferAuditCount()).isZero();
            assertThat(incidents.findById(incident.getId()).orElseThrow().getResponsibleDepartmentId()).isEqualTo(71);
        } finally {
            commit.countDown();
            workers.shutdownNow();
            assertThat(workers.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
        }
    }

    private void prepareTransfer() {
        standard();
        assignments.assign(incident.getId(), handler.getId(), 0L, 1L, "Initial assignment");
        grant(assigner.getId(), "ASSIGN");
        addTransferDestination();
    }

    private void addTransferDestination() {
        db.update("insert into employee_departments(id,display_name,active) values (73,'Operations',1)");
        db.update("insert into employee_department_memberships(department_id,user_id,active) values (73,?,1)", alternate.getId());
        transferRoutes(Set.of(assigner.getId() + ":71:73"));
    }

    private void transferRoutes(Set<String> routes) {
        org.springframework.test.util.ReflectionTestUtils.setField(assignments, "transferScopes", routes);
    }

    private void reconcileFormerHandler() {
        login(classifier);
        administration.setGrant(incident.getId(), handler.getId(), "VIEW", false, 1L, "Approved transfer");
        administration.setGrant(incident.getId(), handler.getId(), "HANDLE", false, 1L, "Approved transfer");
        login(assigner);
    }

    private IncidentTransferRequest transferRequest(long source, long destination, long version, long classificationVersion) {
        return new IncidentTransferRequest(source, destination, alternate.getId(), version, classificationVersion,
                "Routing approved", "REVIEW-42");
    }

    private long transferAuditCount() {
        return db.queryForObject("select count(*) from incident_department_transfer_audit", Long.class);
    }

    @Test
    void globalViewerReadsAllDepartmentsWithAuditButCannotMutateOrManagePermissions() throws Exception {
        long it = incident.getId();
        long hr = createCase(IssueType.HR_ISSUE, 72L);
        long security = createCase(IssueType.INFORMATION_SECURITY_INCIDENT, 71L);
        login(assigner);
        assertThat(incidentService.getAllIncidents()).isEmpty();
        assertThatThrownBy(() -> incidentService.getIncident(hr))
                .isInstanceOf(com.pareidolia.incidentmanagement.exception.IncidentNotFoundException.class);
        assertThatThrownBy(() -> capabilityAdmin.change(assigner.getId(), IncidentAccessPolicy.GLOBAL_INCIDENT_VIEW,
                true, 0L, "Unauthorized")).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);

        var viewer = account("global-viewer@example.test", AppUserRole.REPORTER);
        login(classifier);
        long version = capabilityAdmin.change(viewer.getId(), IncidentAccessPolicy.GLOBAL_INCIDENT_VIEW,
                true, 0L, "Synthetic ISMS approval");
        assertThat(capabilityAdmin.history(viewer.getId(), IncidentAccessPolicy.GLOBAL_INCIDENT_VIEW))
                .singleElement().satisfies(entry -> assertThat(entry.reason()).isEqualTo("Synthetic ISMS approval"));

        login(viewer);
        assertThat(incidentService.getAllIncidents()).extracting(IncidentResponseDto::getId)
                .containsExactlyInAnyOrder(it, hr, security);
        for (long id : List.of(it, hr, security)) {
            var detail = incidentService.getIncident(id);
            assertThat(incidentService.getIncidentByNumber(detail.getIncidentNumber()).getId()).isEqualTo(id);
            assertThat(incidentService.getIncidentHistory(id)).isNotEmpty();
        }
        db.update("""
                insert into incident_attachments(incident_id,original_filename,content_type,file_size,file_data,uploaded_by,uploaded_at)
                values (?, 'synthetic.png', 'image/png', 2, ?, 'synthetic@example.test', current_timestamp)
                """, hr, new byte[]{1,2});
        long attachment = db.queryForObject("select id from incident_attachments where incident_id=?", Long.class, hr);
        assertThat(attachments.list(hr)).hasSize(1);
        assertThat(attachments.content(hr, attachment)).isNotNull();
        var today = java.time.LocalDate.now();
        try (var workbook = new org.apache.poi.xssf.usermodel.XSSFWorkbook(new java.io.ByteArrayInputStream(
                reports.monthly(today.getYear(), today.getMonthValue())))) {
            assertThat(workbook.getSheet("Incidents").getPhysicalNumberOfRows()).isEqualTo(4);
        }
        assertThat(db.queryForList("select distinct operation from incident_global_view_audit where actor_user_id=?",
                String.class, viewer.getId())).contains("LIST", "DETAIL", "NUMBER_LOOKUP", "HISTORY",
                        "ATTACHMENT_LIST", "ATTACHMENT_DOWNLOAD", "REPORT");
        assertThatThrownBy(() -> attachments.upload(hr, List.of()))
                .isInstanceOf(com.pareidolia.incidentmanagement.exception.IncidentNotFoundException.class);
        assertThatThrownBy(() -> incidentService.validateIncident(hr, new ValidateIncidentRequestDto()))
                .isInstanceOf(com.pareidolia.incidentmanagement.exception.IncidentNotFoundException.class);
        assertThatThrownBy(() -> assignments.assign(hr, handler.getId(), 0L, 0L, "View only"))
                .isInstanceOf(ResponseStatusException.class);
        assertThatThrownBy(() -> capabilityAdmin.change(assigner.getId(), IncidentAccessPolicy.GLOBAL_INCIDENT_VIEW,
                true, 0L, "View only")).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);

        login(classifier);
        capabilityAdmin.change(viewer.getId(), IncidentAccessPolicy.GLOBAL_INCIDENT_VIEW, false, version, "Revoked");
        login(viewer);
        assertThat(incidentService.getAllIncidents()).isEmpty();
        assertThatThrownBy(() -> attachments.content(hr, attachment))
                .isInstanceOf(com.pareidolia.incidentmanagement.exception.IncidentNotFoundException.class);
    }

    private long createCase(IssueType type, long department) {
        login(reporter);
        var request = request(null);
        request.setIssueType(type);
        request.setResponsibleDepartmentId(department);
        return incidentService.createIncident(request).getId();
    }

    @Test void creationPersistsOnlyInertProposal(){
        var state=assignments.get(incident.getId());assertThat(state.classification()).isEqualTo("UNCLASSIFIED");assertThat(state.proposal().id()).isEqualTo(handler.getId());assertThat(state.handler()).isNull();assertThat(state.version()).isZero();assertThat(state.canAssign()).isFalse();
        assertThat(incident.getStatus()).isEqualTo(IncidentStatus.OPEN);assertThat(incident.getAssignedOwner()).isNull();assertThat(db.queryForObject("select count(*) from incident_security_grants",Long.class)).isZero();
        login(handler);assertThatThrownBy(()->assignments.get(incident.getId())).isInstanceOf(ResponseStatusException.class);
    }
    @Test void creationWithoutHandlerWorks(){var created=incidentService.createIncident(request(null));var state=assignments.get(created.getId());assertThat(state.proposal()).isNull();assertThat(state.handler()).isNull();assertThat(state.classification()).isEqualTo("UNCLASSIFIED");}
    @Test void eligibleSearchReusesOfficialDirectoryAndEscapesWildcards(){assertThat(assignments.search("HANDLER",null)).extracting(EligibleHandlerDirectory.Employee::id).containsExactly(handler.getId());assertThat(assignments.search("Employee",null)).hasSize(2);assertThat(assignments.search("%_",null)).isEmpty();assertThat(assignments.search("reporter",null)).isEmpty();}
    @Test void invalidInactiveAndIneligibleProposalRollsBackCreation(){long before=incidents.count();db.update("update app_users set active=false where id=?",handler.getId());assertThatThrownBy(()->incidentService.createIncident(request(handler.getId()))).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);assertThat(incidents.count()).isEqualTo(before);assertThatThrownBy(()->incidentService.createIncident(request(reporter.getId()))).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);assertThatThrownBy(()->incidentService.createIncident(request(Long.MAX_VALUE))).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);}
    @Test void classifierCanReviewUnclassifiedButOrdinarySearchesDoNotLeak(){login(classifier);assertThat(assignments.triage()).hasSize(1);assertThat(assignments.triageDetail(incident.getId()).incident().getTitle()).isEqualTo("Synthetic incident");login(assigner);assertThat(assignments.triage()).isEmpty();assertThatThrownBy(()->assignments.triageDetail(incident.getId())).isInstanceOf(ResponseStatusException.class);assertThat(incidentService.getAllIncidents()).isEmpty();}
    @Test void standardAssignmentAndReassignmentUseStableIdsAndAtomicHistory(){standard();var first=assignments.assign(incident.getId(),handler.getId(),0L,1L,"Initial approved handler");assertThat(first.handler().id()).isEqualTo(handler.getId());assertThat(first.version()).isEqualTo(1);assertThat(first.proposal().id()).isEqualTo(handler.getId());var next=assignments.assign(incident.getId(),alternate.getId(),1L,1L,"Different approved handler");assertThat(next.handler().id()).isEqualTo(alternate.getId());assertThat(next.version()).isEqualTo(2);assertThat(assignments.history(incident.getId())).hasSize(2);assertThat(assignments.history(incident.getId()).get(0).previousHandlerId()).isEqualTo(handler.getId());assertThat(incidents.findById(incident.getId()).orElseThrow().getAssignedOwner()).isEqualTo(alternate.getEmail());assertThat(db.queryForObject("select count(*) from incident_history where incident_id=? and action_type='OWNER_ASSIGNED'",Long.class,incident.getId())).isEqualTo(2);}
    @Test void noCapabilityNoViewNoScopeAndNoEligibilityDeny(){standard();login(reporter);assertThatThrownBy(()->assignments.assign(incident.getId(),handler.getId(),0L,1L,"Unauthorized")).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);login(assigner);db.update("update handler_eligibility_grants set active=0 where user_id=?",handler.getId());assertThatThrownBy(()->assignments.assign(incident.getId(),handler.getId(),0L,1L,"No eligibility")).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);org.springframework.test.util.ReflectionTestUtils.setField(assignments,"allowedPairs",Set.of());assertThatThrownBy(()->assignments.assign(incident.getId(),alternate.getId(),0L,1L,"No scope")).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);assertThat(assignments.search("Employee",incident.getId())).isEmpty();}
    @Test void handlerAccessIsRequiredAndIsNeverCreatedByAssignment(){standard();db.update("delete from incident_security_grants where user_id=? and permission='HANDLE'",handler.getId());assertThatThrownBy(()->assignments.assign(incident.getId(),handler.getId(),0L,1L,"Missing case access")).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);assertThat(assignments.get(incident.getId()).handler()).isNull();assertThat(assignments.search("handler",incident.getId())).isEmpty();}
    @Test void unclassifiedAndRestrictedDenyUntilIndependentPermissionsExist(){grant(assigner.getId(),"VIEW");login(assigner);assertThatThrownBy(()->assignments.assign(incident.getId(),handler.getId(),0L,0L,"Unclassified")).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);login(classifier);administration.classify(incident.getId(),"RESTRICTED",0L,"Sensitive case");grant(handler.getId(),"VIEW");grant(handler.getId(),"HANDLE");login(assigner);assertThatThrownBy(()->assignments.assign(incident.getId(),handler.getId(),0L,1L,"No ASSIGN")).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);grant(assigner.getId(),"ASSIGN");assertThat(assignments.assign(incident.getId(),handler.getId(),0L,1L,"Explicit case permissions").handler().id()).isEqualTo(handler.getId());}
    @Test void staleAssignmentAndClassificationVersionsConflict(){standard();assignments.assign(incident.getId(),handler.getId(),0L,1L,"Initial");conflict(()->assignments.assign(incident.getId(),alternate.getId(),0L,1L,"Stale assignment"));conflict(()->assignments.assign(incident.getId(),alternate.getId(),1L,0L,"Stale classification"));}
    @Test void auditFailureRollsBackStateOwnerAndHistory(){standard();db.execute("alter table incident_assignment_audit add constraint synthetic_reject_audit check (assignment_version<1)");try{assertThatThrownBy(()->assignments.assign(incident.getId(),handler.getId(),0L,1L,"Audit rollback")).isInstanceOf(RuntimeException.class);assertThat(assignments.get(incident.getId()).handler()).isNull();assertThat(assignments.get(incident.getId()).version()).isZero();assertThat(incidents.findById(incident.getId()).orElseThrow().getAssignedOwner()).isNull();}finally{db.execute("alter table incident_assignment_audit drop constraint synthetic_reject_audit");}}
    @Test void monitorCannotAssignAndLegacyEndpointAlwaysDenied(){standard();login(handler);assertThatThrownBy(()->assignments.assign(incident.getId(),alternate.getId(),0L,1L,"Monitor")).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);assertThatThrownBy(()->incidentService.assignIncident(incident.getId(),new AssignIncidentRequestDto())).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);}
    @Test void twoConcurrentAssignmentsCannotLoseAnUpdate()throws Exception{standard();var pool=Executors.newFixedThreadPool(2);var start=new CountDownLatch(1);try{var tasks=List.of(handler,alternate).stream().map(target->pool.submit(()->{login(assigner);try{start.await();assignments.assign(incident.getId(),target.getId(),0L,1L,"Concurrent");return true;}catch(ResponseStatusException e){assertThat(e.getStatusCode().value()).isEqualTo(409);return false;}finally{SecurityContextHolder.clearContext();}})).toList();start.countDown();int successes=0;for(var task:tasks)if(task.get(10,TimeUnit.SECONDS))successes++;assertThat(successes).isEqualTo(1);assertThat(assignments.get(incident.getId()).version()).isEqualTo(1);}finally{pool.shutdownNow();}}
    @Test void revocationLinearizesBeforeWaitingAssignment()throws Exception{standard();var locked=new CountDownLatch(1);var release=new CountDownLatch(1);var pool=Executors.newFixedThreadPool(2);try{var writer=pool.submit(()->{var transaction=new org.springframework.transaction.support.TransactionTemplate(transactionManager);transaction.executeWithoutResult(status->{gate.write();login(classifier);administration.setGrant(incident.getId(),handler.getId(),"HANDLE",false,1L,"Concurrent synthetic revocation");locked.countDown();try{if(!release.await(10,TimeUnit.SECONDS))throw new IllegalStateException();}catch(InterruptedException e){throw new IllegalStateException(e);}});});assertThat(locked.await(10,TimeUnit.SECONDS)).isTrue();var assignment=pool.submit(()->{login(assigner);try{return assignments.assign(incident.getId(),handler.getId(),0L,1L,"Concurrent revoke");}finally{SecurityContextHolder.clearContext();}});assertThatThrownBy(()->assignment.get(250,TimeUnit.MILLISECONDS)).isInstanceOf(TimeoutException.class);release.countDown();writer.get(10,TimeUnit.SECONDS);assertThatThrownBy(()->assignment.get(10,TimeUnit.SECONDS)).hasCauseInstanceOf(org.springframework.security.access.AccessDeniedException.class);assertThat(assignments.get(incident.getId()).handler()).isNull();}finally{release.countDown();pool.shutdownNow();}}
    @Test void deactivationAndUnverifiedOidcDenyCurrentAssignment(){standard();db.update("update app_users set active=false where id=?",handler.getId());assertThatThrownBy(()->assignments.assign(incident.getId(),handler.getId(),0L,1L,"Inactive")).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);var oidc=mock(OidcUser.class);when(oidc.getEmail()).thenReturn(assigner.getEmail());when(oidc.getEmailVerified()).thenReturn(false);SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(oidc,"",List.of()));assertThatThrownBy(()->assignments.get(incident.getId())).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);}
    @Test void effectiveHandlerCanResolveButOnlyOriginalReporterCanValidateAndClose(){
        standard();assignments.assign(incident.getId(),handler.getId(),0L,1L,"Approved");login(handler);
        var resolve=new ResolveIncidentRequestDto();resolve.setResolutionDetails("Fixed synthetic issue");assertThat(incidentService.resolveIncident(incident.getId(),resolve).getStatus()).isEqualTo(IncidentStatus.RESOLVED);
        var validation=new ValidateIncidentRequestDto();validation.setValidationDetails("Verified synthetic issue");assertThatThrownBy(()->incidentService.validateIncident(incident.getId(),validation)).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
        login(reporter);assertThat(incidentService.validateIncident(incident.getId(),validation).getStatus()).isEqualTo(IncidentStatus.VALIDATED);assertThat(incidentService.closeIncident(incident.getId(),new CloseIncidentRequestDto()).getStatus()).isEqualTo(IncidentStatus.CLOSED);
        login(assigner);assertThatThrownBy(()->assignments.assign(incident.getId(),alternate.getId(),1L,1L,"Closed incident")).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
    }
    @Test void legacyMissingClassificationRequiresTriageAndNeverInfersIdentityFromOwner(){
        db.update("delete from incident_assignment_state where incident_id=?",incident.getId());db.update("delete from incident_security_classification where incident_id=?",incident.getId());db.update("update incidents set assigned_owner=? where id=?",handler.getEmail(),incident.getId());
        assertThatThrownBy(() -> assignments.get(incident.getId())).isInstanceOf(ResponseStatusException.class);standard();assertThat(assignments.get(incident.getId()).handler()).isNull();assertThat(assignments.assign(incident.getId(),alternate.getId(),0L,1L,"Explicit legacy triage").handler().id()).isEqualTo(alternate.getId());assertThat(assignments.history(incident.getId()).get(0).previousHandlerId()).isNull();
    }
    @Test void capabilityAndActorDeactivationAreRechecked(){
        standard();db.update("update assignment_admin_capabilities set active=0 where user_id=? and capability='ASSIGNMENT_ADMIN'",assigner.getId());assertThatThrownBy(()->assignments.assign(incident.getId(),handler.getId(),0L,1L,"Revoked capability")).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
        db.update("update app_users set active=false where id=?",assigner.getId());assertThatThrownBy(()->assignments.get(incident.getId())).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
    }
    @Test void classificationChangeCannotReuseOldApproval(){
        standard();login(classifier);administration.classify(incident.getId(),"RESTRICTED",1L,"Changed sensitivity");login(assigner);assertThatThrownBy(()->assignments.assign(incident.getId(),handler.getId(),0L,1L,"Old standard approval")).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);assertThat(assignments.get(incident.getId()).handler()).isNull();
    }
    @Test void defaultOffCreationStillUsesConfiguredV2OwnerAndRejectsNewProposal(){
        org.springframework.test.util.ReflectionTestUtils.setField(incidentService,"employeeAssignmentEnabled",false);
        org.springframework.test.util.ReflectionTestUtils.setField(incidentService,"incidentAccessEnabled",false);
        try{login(reporter);var legacy=request(null);legacy.setResponsibleDepartmentId(null);var result=incidentService.createIncident(legacy);assertThat(result.getAssignedOwner()).isEqualTo("legacy@example.test");assertThat(result.getStatus()).isEqualTo(IncidentStatus.ASSIGNED);assertThat(db.queryForObject("select count(*) from incident_assignment_state where incident_id=?",Long.class,result.getId())).isZero();assertThatThrownBy(()->incidentService.createIncident(request(handler.getId()))).isInstanceOf(IllegalArgumentException.class);}
        finally{
            org.springframework.test.util.ReflectionTestUtils.setField(incidentService,"employeeAssignmentEnabled",true);
            org.springframework.test.util.ReflectionTestUtils.setField(incidentService,"incidentAccessEnabled",true);
        }
    }
    @Test
    void hrCaseRemainsPendingAndRequiresRestrictedGrantsAndActiveMembership() {
        var request = request(null);
        request.setIssueType(IssueType.HR_ISSUE);
        request.setResponsibleDepartmentId(72L);
        var created = incidentService.createIncident(request);
        incident = incidents.findById(created.getId()).orElseThrow();
        assertThat(created.getAssignedOwner()).isNull();
        assertThat(created.getStatus()).isEqualTo(IncidentStatus.OPEN);
        assertThat(history.findByIncidentIdOrderByChangedAtAscIdAsc(incident.getId()))
                .extracting(entry -> entry.getActionType().name()).containsExactly("INCIDENT_CREATED");

        login(assigner);
        assertThat(incidentService.getAllIncidents()).isEmpty();
        assertThatThrownBy(() -> incidentService.getIncident(incident.getId())).isInstanceOf(
                com.pareidolia.incidentmanagement.exception.IncidentNotFoundException.class);
        assertThatThrownBy(() -> attachments.list(incident.getId())).isInstanceOf(
                com.pareidolia.incidentmanagement.exception.IncidentNotFoundException.class);
        assertThatThrownBy(() -> attachments.content(incident.getId(), 1L)).isInstanceOf(
                com.pareidolia.incidentmanagement.exception.IncidentNotFoundException.class);
        assertThatThrownBy(() -> attachments.upload(incident.getId(), List.of())).isInstanceOf(
                com.pareidolia.incidentmanagement.exception.IncidentNotFoundException.class);

        login(classifier);
        administration.classify(incident.getId(), "RESTRICTED", 0L, "Synthetic restricted intake");
        grant(assigner.getId(), "VIEW"); grant(assigner.getId(), "ASSIGN");
        for (var target : List.of(handler, assigner)) {
            if (!target.getId().equals(assigner.getId())) grant(target.getId(), "VIEW");
            grant(target.getId(), "HANDLE");
        }
        db.update("insert into handler_eligibility_grants(user_id,active,version) values (?,1,0)", assigner.getId());
        org.springframework.test.util.ReflectionTestUtils.setField(assignments, "allowedPairs",
                Set.of(assigner.getId() + ":" + handler.getId(), assigner.getId() + ":" + assigner.getId()));
        login(assigner);
        assertThatThrownBy(() -> assignments.assign(incident.getId(), assigner.getId(), 0L, 1L, "No HR membership"))
                .isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
        assertThatThrownBy(() -> assignments.assign(incident.getId(), handler.getId(), 0L, 1L, "Only IT membership"))
                .isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
        db.update("insert into employee_department_memberships(department_id,user_id,active) values (72,?,1)", handler.getId());
        assertThat(assignments.assign(incident.getId(), handler.getId(), 0L, 1L, "Approved HR handler").handler().id())
                .isEqualTo(handler.getId());
        assertThat(assignments.history(incident.getId())).singleElement().satisfies(audit -> {
            assertThat(audit.actorId()).isEqualTo(assigner.getId());
            assertThat(audit.previousHandlerId()).isNull();
            assertThat(audit.newHandlerId()).isEqualTo(handler.getId());
            assertThat(audit.reason()).isEqualTo("Approved HR handler");
        });
    }

    @Test
    void missingOrInactiveResponsibleDepartmentCannotAuthorizeAssignment() {
        standard();
        db.update("update employee_departments set active=0 where id=71");
        assertThatThrownBy(() -> assignments.assign(incident.getId(), handler.getId(), 0L, 1L, "Inactive department"))
                .isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
        db.update("update incidents set responsible_department_id=null where id=?", incident.getId());
        assertThatThrownBy(() -> assignments.assign(incident.getId(), handler.getId(), 0L, 1L, "Missing department"))
                .isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
    }

    @Test void httpContractsUseStableIdsAndValidatedVersions()throws Exception{
        standard();var mvc=org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup(new com.pareidolia.incidentmanagement.controller.IncidentAssignmentController(assignments)).setControllerAdvice(new com.pareidolia.incidentmanagement.exception.GlobalExceptionHandler()).build();
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/incident-assignment/handlers").param("search","handler").param("incidentId",String.valueOf(incident.getId()))).andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk()).andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$[0].id").value(handler.getId()));
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/api/incident-assignment/"+incident.getId()).contentType("application/json").content("{\"handlerUserId\":"+handler.getId()+",\"expectedVersion\":0,\"expectedClassificationVersion\":1,\"reason\":\"HTTP approval\"}")).andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk()).andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.handler.id").value(handler.getId()));
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/api/incident-assignment/"+incident.getId()).contentType("application/json").content("{\"handlerUserId\":8,\"reason\":\"\"}")).andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isBadRequest());
    }
    @Test void activationGuardStillRefusesFullApplicationEnablement(){assertThatThrownBy(()->new IncidentAccessActivationGuard(true)).isInstanceOf(IllegalStateException.class);}    @Test void assignmentReadEndpointsPreserveLegacyReporterOwnershipRestriction(){
        standard();db.update("update app_users set role='REPORTER' where id=?",assigner.getId());login(assigner);
        assertThat(assignments.triage()).isEmpty();assertThatThrownBy(()->assignments.get(incident.getId())).isInstanceOf(ResponseStatusException.class);assertThatThrownBy(()->assignments.history(incident.getId())).isInstanceOf(ResponseStatusException.class);assertThatThrownBy(()->assignments.triageDetail(incident.getId())).isInstanceOf(ResponseStatusException.class);assertThatThrownBy(()->assignments.assign(incident.getId(),handler.getId(),0L,1L,"Reporter boundary")).isInstanceOf(ResponseStatusException.class);
    }

@Test
void schemaEnforcesStableForeignKeysVersionUniquenessAndNonblankReasons() {
    long id = incident.getId();

    // Foreign-key enforcement: an unknown handler must be rejected.
    assertThatThrownBy(() ->
        db.update(
            "update incident_assignment_state set handler_user_id=? where incident_id=?",
            Long.MAX_VALUE,
            id
        )
    ).isInstanceOf(
        org.springframework.dao.DataIntegrityViolationException.class
    );

    String insert =
        "insert into incident_assignment_audit" +
        "(incident_id,actor_user_id,new_handler_user_id," +
        "assignment_version,action_type,reason) " +
        "values (?,?,?,1,'INITIAL',?)";

    // A blank audit reason must be rejected by the database.
    assertThatThrownBy(() ->
        db.update(insert, id, assigner.getId(), handler.getId(), " ")
    ).satisfies(error -> {

        // H2 and some JDBC drivers use this exception.
        if (error instanceof
            org.springframework.dao.DataIntegrityViolationException) {
            return;
        }

        // MySQL 8.4 may report CHECK constraint error 3819
        // through Spring's UncategorizedSQLException.
        assertThat(error).isInstanceOf(
            org.springframework.jdbc.UncategorizedSQLException.class
        );

        var sqlException =
            ((org.springframework.jdbc.UncategorizedSQLException) error)
                .getSQLException();

        assertThat(sqlException.getErrorCode()).isEqualTo(3819);
        assertThat(sqlException.getMessage())
            .contains("ck_assignment_reason");
    });

    // A valid reason must be accepted.
    db.update(
        insert,
        id,
        assigner.getId(),
        handler.getId(),
        "Synthetic constraint check"
    );

    // Duplicate assignment versions must be rejected.
    assertThatThrownBy(() ->
        db.update(
            insert,
            id,
            assigner.getId(),
            alternate.getId(),
            "Duplicate version"
        )
    ).isInstanceOf(
        org.springframework.dao.DataIntegrityViolationException.class
    );
}

}
