package com.pareidolia.incidentmanagement.b4browser;

import com.pareidolia.incidentmanagement.service.AppUserService;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class B4BrowserPreflightTests {
    private static final String REPORTER = "reporter@example.test";

    @Test
    void acceptsExistingOwnedFixtureButRejectsMissingOrMismatchedCreationAudit() throws Exception {
        try (var connection = DriverManager.getConnection("jdbc:h2:mem:" + UUID.randomUUID());
             var sql = connection.createStatement()) {
            sql.execute("create table app_users(email varchar(100))");
            sql.execute("create table incidents(id bigint, reported_by varchar(100), incident_number varchar(50))");
            sql.execute("create table incident_history(incident_id bigint, action_type varchar(30), changed_by varchar(100))");
            B4BrowserPreflight.verifyFixtureOwnership(connection, List.of(REPORTER));
            sql.execute("insert into app_users values ('reporter@example.test')");
            sql.execute("insert into incidents values (1, 'reporter@example.test', 'INC-20261110-180300-0123ABCD')");
            assertThatThrownBy(() -> B4BrowserPreflight.verifyFixtureOwnership(connection, List.of(REPORTER)))
                    .isInstanceOf(IllegalStateException.class);
            sql.execute("insert into incident_history values (1, 'INCIDENT_CREATED', 'reporter@example.test')");
            B4BrowserPreflight.verifyFixtureOwnership(connection, List.of(REPORTER));
            sql.execute("update incidents set reported_by='other@example.test'");
            assertThatThrownBy(() -> B4BrowserPreflight.verifyFixtureOwnership(connection, List.of(REPORTER)))
                    .isInstanceOf(IllegalStateException.class);
            sql.execute("update incidents set reported_by='reporter@example.test'");
            sql.execute("insert into app_users values ('other@example.test')");
            assertThatThrownBy(() -> B4BrowserPreflight.verifyFixtureOwnership(connection, List.of(REPORTER)))
                    .isInstanceOf(IllegalStateException.class);
        }
    }

    @Test
    void pinsServerIdentityEvenWhenSchemaAndAccountNamesMatch() throws Exception {
        var connection = mock(Connection.class);
        var statement = mock(Statement.class);
        var result = mock(ResultSet.class);
        when(connection.createStatement()).thenReturn(statement);
        when(statement.executeQuery(anyString())).thenReturn(result);
        when(result.next()).thenReturn(true, false, true, false);
        when(result.getString(1)).thenReturn("incident_security_disposable");
        when(result.getString(2)).thenReturn("11111111-1111-1111-1111-111111111111");
        when(result.getString(3)).thenReturn("8.4.11");
        when(result.getString(4)).thenReturn("b4_browser_test");
        when(result.getInt(5)).thenReturn(32);
        when(result.getInt(6)).thenReturn(1);
        when(result.getInt(7)).thenReturn(1);
        B4BrowserPreflight.verifyDatabase(connection, "11111111-1111-1111-1111-111111111111");
        assertThatThrownBy(() -> B4BrowserPreflight.verifyDatabase(connection, "22222222-2222-2222-2222-222222222222"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void ignoresAmbientSpringDatasourceAndMailOverrides() {
        System.setProperty("spring.application.json", "{\"app.notifications.email.enabled\":true}");
        System.setProperty("spring.datasource.hikari.jdbc-url", "jdbc:mysql://other.invalid/example");
        try {
            var settings = new B4BrowserPreflight.Settings("jdbc:mysql://127.0.0.1:59450/incident_security_disposable",
                    "b4_browser_test", "synthetic", "11111111-1111-1111-1111-111111111111", List.of(REPORTER));
            var environment = B4BrowserTestServer.isolatedEnvironment(settings);
            assertThat(environment.getProperty("spring.datasource.url")).isEqualTo(settings.url());
            assertThat(environment.getProperty("spring.datasource.hikari.jdbc-url")).isNull();
            assertThat(environment.getProperty("spring.application.json")).isNull();
            assertThat(environment.getProperty("app.notifications.email.enabled")).isEqualTo("false");
            assertThat(environment.getProperty("server.address")).isEqualTo("127.0.0.1");
        } finally {
            System.clearProperty("spring.application.json");
            System.clearProperty("spring.datasource.hikari.jdbc-url");
        }
    }

    @Test
    void rejectsUnapprovedLoginBeforeAccountProvisioning() throws Exception {
        var users = mock(AppUserService.class);
        var handler = new B4BrowserTestServer.FixtureAuthenticationSuccessHandler(users, List.of(REPORTER));
        var request = new MockHttpServletRequest();
        var response = new MockHttpServletResponse();
        var authentication = mock(Authentication.class);
        var principal = mock(OidcUser.class);
        when(authentication.getPrincipal()).thenReturn(principal);
        when(principal.getEmailVerified()).thenReturn(true);
        when(principal.getEmail()).thenReturn("other@example.test");
        var session = (org.springframework.mock.web.MockHttpSession) request.getSession();
        handler.onAuthenticationSuccess(request, response, authentication);
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(session.isInvalid()).isTrue();
        verifyNoInteractions(users);

        when(principal.getEmail()).thenReturn(REPORTER);
        var allowed = new MockHttpServletResponse();
        handler.onAuthenticationSuccess(new MockHttpServletRequest(), allowed, authentication);
        assertThat(allowed.getRedirectedUrl()).isEqualTo("http://127.0.0.1:5175");
        verify(users).provisionUser(principal);
    }
}
