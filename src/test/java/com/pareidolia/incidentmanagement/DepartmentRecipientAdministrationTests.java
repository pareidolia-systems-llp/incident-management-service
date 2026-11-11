package com.pareidolia.incidentmanagement;

import com.pareidolia.incidentmanagement.entity.AppUser;
import com.pareidolia.incidentmanagement.security.EmployeeManagementAccess;
import com.pareidolia.incidentmanagement.service.AppUserService;
import com.pareidolia.incidentmanagement.service.DepartmentRecipientAdministrationService;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class DepartmentRecipientAdministrationTests {
    private final AppUserService users = mock(AppUserService.class);
    private final EmployeeManagementAccess access = mock(EmployeeManagementAccess.class);
    private JdbcTemplate db;
    private TransactionTemplate transaction;
    private DepartmentRecipientAdministrationService service;

    @BeforeEach void initialize() {
        var source = new DriverManagerDataSource("jdbc:h2:mem:" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1", "sa", "");
        db = new JdbcTemplate(source);
        transaction = new TransactionTemplate(new DataSourceTransactionManager(source));
        service = new DepartmentRecipientAdministrationService(db, users, access, mock(com.pareidolia.incidentmanagement.security.IncidentSecurityGate.class), false);
        db.execute("create table app_users(id bigint primary key,email varchar(254),active boolean)");
        db.execute("create table employee_mapping_admins(user_id bigint primary key,active boolean)");
        db.execute("create table employee_departments(id bigint primary key,display_name varchar(150),active boolean)");
        db.execute("""
                create table incident_department_mail_recipient(
                    id char(36) primary key,department_id bigint,email varchar(254),active boolean,version bigint,
                    unique(department_id,email))
                """);
        db.execute("""
                create table incident_department_mail_recipient_audit(
                    recipient_id char(36),actor_user_id bigint,old_email varchar(254),new_email varchar(254),
                    old_active boolean,new_active boolean,version bigint,reason varchar(500),
                    changed_at timestamp default current_timestamp,primary key(recipient_id,version))
                """);
        db.update("insert into app_users values(1,'admin@example.test',true)");
        db.update("insert into employee_mapping_admins values(1,true)");
        db.update("insert into employee_departments values(7,'IT',true),(8,'Unapproved',true)");
        var actor = new AppUser();
        actor.setId(1L);
        actor.setEmail("admin@example.test");
        when(users.getAuthenticatedUser()).thenReturn(actor);
        when(access.canManage(actor)).thenReturn(true);
    }

    @Test void addsUpdatesAndDeactivatesWithVersionAndAudit() {
        UUID id = transaction.execute(status -> service.add(7, "TEAM@example.test", "Approved initial route"));
        assertThat(service.list().recipients()).singleElement().satisfies(recipient -> {
            assertThat(recipient.email()).isEqualTo("team@example.test");
            assertThat(recipient.version()).isZero();
        });
        assertThatThrownBy(() -> transaction.executeWithoutResult(status ->
                service.add(7, "team@example.test", "Duplicate"))).isInstanceOfSatisfying(ResponseStatusException.class,
                failure -> assertThat(failure.getStatusCode().value()).isEqualTo(409));
        transaction.executeWithoutResult(status -> service.update(id, "replacement@example.test", true, 0, "Mailbox changed"));
        assertThatThrownBy(() -> transaction.executeWithoutResult(status ->
                service.update(id, "replacement@example.test", false, 0, "Stale edit")))
                .isInstanceOfSatisfying(ResponseStatusException.class, failure -> assertThat(failure.getStatusCode().value()).isEqualTo(409));
        transaction.executeWithoutResult(status -> service.update(id, "replacement@example.test", false, 1, "Mailbox retired"));
        assertThat(service.history(id)).extracting(DepartmentRecipientAdministrationService.Audit::reason)
                .containsExactly("Mailbox retired", "Mailbox changed", "Approved initial route");
        assertThat(service.history(id).get(0)).satisfies(audit -> {
            assertThat(audit.actorUserId()).isEqualTo(1L);
            assertThat(audit.oldActive()).isTrue();
            assertThat(audit.newActive()).isFalse();
        });
    }

    @Test void requiresVerifiedPersonnelAccessAndAnActiveMappingCapability() {
        db.update("update employee_mapping_admins set active=false");
        assertThatThrownBy(service::list).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> service.add(7, "team@example.test", "Attempt")).isInstanceOf(AccessDeniedException.class);
        db.update("update employee_mapping_admins set active=true");
        when(access.canManage(any())).thenReturn(false);
        assertThatThrownBy(service::list).isInstanceOf(AccessDeniedException.class);
    }

    @Test void rejectsInvalidRequestsAndRollsBackWhenAuditWriteFails() {
        assertThatThrownBy(() -> service.add(8, "team@example.test", "Unknown department"))
                .isInstanceOf(ResponseStatusException.class);
        assertThatThrownBy(() -> service.add(7, "team@example.test", " ")).isInstanceOf(ResponseStatusException.class);
        assertThatThrownBy(() -> service.add(7, "one@example.test,two@example.test", "Multiple addresses"))
                .isInstanceOf(ResponseStatusException.class);
        db.execute("drop table incident_department_mail_recipient_audit");
        assertThatThrownBy(() -> transaction.execute(status -> service.add(7, "team@example.test", "Audit unavailable")))
                .isInstanceOf(org.springframework.dao.DataAccessException.class);
        assertThat(service.list().recipients()).isEmpty();
    }
}
