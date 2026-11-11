package com.pareidolia.incidentmanagement.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pareidolia.incidentmanagement.security.IncidentSecurityGate;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

/** Opt-in only. Requires pre-seeded synthetic actors and a duplicate audit version on the failure fixture. */
@EnabledIfEnvironmentVariable(named = "INCIDENT_MEMBERSHIP_POC_MYSQL", matches = "true")
@SpringBootTest(properties = {
        "spring.jpa.hibernate.ddl-auto=validate", "app.incident-access.enabled=false",
        "app.department-membership-admin.enabled=true", "app.department-membership-admin.dedicated-command.enabled=true",
        "app.department-membership-admin.allowed-emails=membership-poc-actor@example.test",
        "app.notifications.email.enabled=false", "app.notifications.email.v2.enabled=false",
        "app.notifications.email.local-postfix-enabled=false"
})
class MembershipCommandMysqlTests {
    private static final String ACTOR = "membership-poc-actor@example.test";
    private static final String TARGET = "membership-poc-target@example.test";
    private static final String FAILURE = "membership-poc-failure@example.test";
    private static final String RACE = "membership-poc-race@example.test";
    private static final String URL_PATTERN =
            "jdbc:mysql://127[.]0[.]0[.]1:[0-9]+/incident_browser_34058e782e8c4b79928a2585ec799a05([?].*)?";

    @DynamicPropertySource
    static void verifyLocalUrls(DynamicPropertyRegistry registry) {
        String url = System.getenv("DB_URL");
        if (url == null || !url.matches(URL_PATTERN) || !url.equals(System.getenv("DEPARTMENT_MEMBERSHIP_COMMAND_DB_URL"))) {
            throw new IllegalStateException("The membership proof requires the confirmed disposable loopback schema.");
        }
        registry.add("spring.datasource.url", () -> url);
        registry.add("app.department-membership-admin.dedicated-command.url", () -> url);
    }

    @MockitoBean
    OAuth2AuthorizedClientManager authorizedClientManager;

    @MockitoBean
    OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> tokenClient;

    @Autowired DepartmentMembershipAdminService memberships;
    @Autowired JdbcTemplate db;
    @Autowired DataSource ordinary;
    @Autowired PlatformTransactionManager ordinaryManager;

    @AfterEach
    void clearIdentity() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void ownsDedicatedTransactionAndEnforcesAuthorizationAndVersions() {
        long department = department();
        long target = user(TARGET);
        String runtimeUser = db.queryForObject("select current_user()", String.class);
        assertThat(runtimeUser).startsWith(System.getenv("DB_USER") + "@");
        assertThatThrownBy(() -> db.update("""
                update employee_department_memberships set active=0 where 1=0
                """)).isInstanceOf(DataAccessException.class);
        assertThatThrownBy(() -> db.update("""
                update employee_department_membership_audit set reason='forbidden' where 1=0
                """)).isInstanceOf(DataAccessException.class);
        assertThatThrownBy(() -> new MembershipCommandConnection(ordinary, System.getenv("DB_URL"),
                System.getenv("DB_USER"), System.getenv("DB_PASS"))).isInstanceOf(IllegalStateException.class);

        login(TARGET, true);
        assertThatThrownBy(() -> memberships.change(department, target, true, 0L, "Unlisted"))
                .isInstanceOf(AccessDeniedException.class);
        login(ACTOR, false);
        assertThatThrownBy(() -> memberships.change(department, target, true, 0L, "Unverified"))
                .isInstanceOf(AccessDeniedException.class);

        login(ACTOR, true);
        assertThatThrownBy(() -> new TransactionTemplate(ordinaryManager).execute(status ->
                memberships.change(department, target, true, 0L, "Ambient transaction")))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("own its transaction");
        assertThatThrownBy(() -> memberships.change(department, target, true, 0L, " "))
                .isInstanceOfSatisfying(ResponseStatusException.class, error -> assertThat(error.getStatusCode().value()).isEqualTo(400));
        assertThat(memberships.change(department, target, true, 0L, "Synthetic grant")).isEqualTo(1);
        assertThatThrownBy(() -> memberships.change(department, target, false, 0L, "Stale revoke"))
                .isInstanceOfSatisfying(ResponseStatusException.class, error -> assertThat(error.getStatusCode().value()).isEqualTo(409));
        assertThat(memberships.change(department, target, false, 1L, "Synthetic revoke")).isEqualTo(2);
        assertThat(membershipState(department, target)).isEqualTo("0:2");
    }

    @Test
    void auditFailureRollsBackTheMembershipUpdate() {
        long department = department();
        long target = user(FAILURE);
        login(ACTOR, true);
        assertThatThrownBy(() -> memberships.change(department, target, false, 1L, "Duplicate audit version"))
                .isInstanceOf(DataIntegrityViolationException.class);
        assertThat(membershipState(department, target)).isEqualTo("1:1");
    }

    private String membershipState(long department, long target) {
        return db.queryForObject("""
                select concat(active, ':', version) from employee_department_memberships
                where department_id=? and user_id=?
                """, String.class, department, target);
    }

    @Test
    void assignmentGateWaitsAndRechecksRevocationOnTheOtherConnection() throws Exception {
        long department = department();
        long target = user(RACE);
        var workers = Executors.newFixedThreadPool(2);
        try (var blocker = ordinary.getConnection(); var observer = ordinary.getConnection()) {
            blocker.setAutoCommit(false);
            observer.setAutoCommit(false);
            try {
                // Hold only the membership row so the real command holds the gate while it waits.
                assertThat(scalar(blocker, """
                        select active from employee_department_memberships
                        where department_id=? and user_id=? for share
                        """, department, target)).isEqualTo(1);
                var revoke = workers.submit(() -> {
                    login(ACTOR, true);
                    try {
                        return memberships.change(department, target, false, 1L, "Racing revoke");
                    } finally {
                        SecurityContextHolder.clearContext();
                    }
                });
                waitForExclusiveGate(observer);
                var assignmentCheck = workers.submit(() -> {
                    try (var connection = ordinary.getConnection()) {
                        connection.setAutoCommit(false);
                        try {
                            scalar(connection, IncidentSecurityGate.EXCLUSIVE_LOCK_SQL);
                            return scalar(connection, """
                                    select active from employee_department_memberships
                                    where department_id=? and user_id=? for share
                                    """, department, target);
                        } finally {
                            connection.rollback();
                        }
                    }
                });
                assertThatThrownBy(() -> assignmentCheck.get(200, TimeUnit.MILLISECONDS))
                        .isInstanceOf(java.util.concurrent.TimeoutException.class);
                blocker.rollback();
                assertThat(revoke.get(10, TimeUnit.SECONDS)).isEqualTo(2);
                assertThat(assignmentCheck.get(10, TimeUnit.SECONDS)).isZero();
            } finally {
                blocker.rollback();
                observer.rollback();
            }
        } finally {
            workers.shutdownNow();
            assertThat(workers.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
        }
    }

    private long department() {
        return db.queryForObject("select min(id) from employee_departments where active=1", Long.class);
    }

    private long user(String email) {
        return db.queryForObject("select id from app_users where email=?", Long.class, email);
    }

    private static void waitForExclusiveGate(Connection observer) throws Exception {
        for (int attempt = 0; attempt < 100; attempt++) {
            try {
                scalar(observer, "select id from incident_security_lock where id=1 for share nowait");
            } catch (SQLException expected) {
                if (expected.getErrorCode() == 3572) return;
                throw expected;
            } finally {
                observer.rollback();
            }
            Thread.sleep(30);
        }
        throw new AssertionError("The dedicated membership command did not lock the shared gate.");
    }

    private static long scalar(Connection connection, String sql, long... parameters) throws SQLException {
        try (var statement = connection.prepareStatement(sql)) {
            for (int index = 0; index < parameters.length; index++) statement.setLong(index + 1, parameters[index]);
            try (var rows = statement.executeQuery()) {
                if (!rows.next()) throw new AssertionError("Fixture row missing.");
                return rows.getLong(1);
            }
        }
    }

    private static void login(String email, boolean verified) {
        var oidc = mock(OidcUser.class);
        when(oidc.getEmail()).thenReturn(email);
        when(oidc.getEmailVerified()).thenReturn(verified);
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(oidc, "", List.of()));
    }
}
