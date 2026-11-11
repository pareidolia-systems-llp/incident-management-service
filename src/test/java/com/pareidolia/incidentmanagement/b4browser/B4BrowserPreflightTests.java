package com.pareidolia.incidentmanagement.b4browser;

import com.pareidolia.incidentmanagement.service.AppUserService;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.context.TypeExcludeFilter;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
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
        when(result.getInt(5)).thenReturn(34);
        when(result.getInt(6)).thenReturn(1);
        when(result.getInt(7)).thenReturn(1);
        when(result.getInt(8)).thenReturn(2);
        B4BrowserPreflight.verifyDatabase(connection, "11111111-1111-1111-1111-111111111111");
        assertThatThrownBy(() -> B4BrowserPreflight.verifyDatabase(connection, "22222222-2222-2222-2222-222222222222"))
                .isInstanceOf(IllegalStateException.class);
        verify(statement, times(2)).executeQuery(argThat(sql -> sql.contains("incident_department_head_email_receipt")
                && sql.contains("incident_oversight_notification")));

        when(result.next()).thenReturn(true, false);
        when(result.getInt(8)).thenReturn(1);
        assertThatThrownBy(() -> B4BrowserPreflight.verifyDatabase(connection, "11111111-1111-1111-1111-111111111111"))
                .isInstanceOf(IllegalStateException.class);
        when(result.getInt(8)).thenReturn(2);
        when(result.next()).thenReturn(true, false);
        when(result.getInt(5)).thenReturn(32);
        assertThatThrownBy(() -> B4BrowserPreflight.verifyDatabase(connection, "11111111-1111-1111-1111-111111111111"))
                .isInstanceOf(IllegalStateException.class);
        when(result.next()).thenReturn(true, false);
        when(result.getInt(5)).thenReturn(36);
        when(result.getInt(9)).thenReturn(2);
        assertThat(B4BrowserPreflight.verifyDatabase(connection, "11111111-1111-1111-1111-111111111111")).isTrue();
        when(result.next()).thenReturn(true, false);
        when(result.getInt(9)).thenReturn(1);
        assertThatThrownBy(() -> B4BrowserPreflight.verifyDatabase(connection, "11111111-1111-1111-1111-111111111111"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void standaloneComponentScanExcludesTestConfigurationAndKeepsRealUserService() {
        var scanner = new ClassPathScanningCandidateComponentProvider(true);
        var beanFactory = new DefaultListableBeanFactory();
        beanFactory.registerSingleton("b4TestComponentExclusion", new B4BrowserTestServer.TestComponentExclusion());
        var bootFilter = new TypeExcludeFilter();
        bootFilter.setBeanFactory(beanFactory);
        scanner.addExcludeFilter(bootFilter);

        assertThat(scanner.findCandidateComponents("com.pareidolia.incidentmanagement"))
                .extracting(candidate -> candidate.getBeanClassName())
                .contains(AppUserService.class.getName())
                .doesNotContain("com.pareidolia.incidentmanagement.AuthenticationFlowTests$Config");
    }

    @Test
    void ignoresAmbientSpringDatasourceAndMailOverrides() {
        String previousEmployeeAllowlist = System.setProperty("app.employee-management.allowed-emails", REPORTER);
        System.setProperty("spring.application.json", "{\"app.notifications.email.enabled\":true}");
        System.setProperty("spring.datasource.hikari.jdbc-url", "jdbc:mysql://other.invalid/example");
        try {
            var settings = new B4BrowserPreflight.Settings("jdbc:mysql://127.0.0.1:59450/incident_security_disposable",
                    "b4_browser_test", "synthetic", "11111111-1111-1111-1111-111111111111", List.of(REPORTER), false);
            var environment = B4BrowserTestServer.isolatedEnvironment(settings);
            assertThat(environment.getProperty("spring.datasource.url")).isEqualTo(settings.url());
            assertThat(environment.getProperty("spring.datasource.hikari.jdbc-url")).isNull();
            assertThat(environment.getProperty("spring.application.json")).isNull();
            assertThat(environment.getProperty("app.employee-management.allowed-emails")).isEmpty();
            assertThat(environment.getProperty("app.notifications.email.enabled")).isEqualTo("false");
            assertThat(environment.getProperty("app.employee-assignment.active-email-search.enabled")).isEqualTo("true");
            assertThat(environment.getProperty("server.address")).isEqualTo("127.0.0.1");
        } finally {
            if (previousEmployeeAllowlist == null) System.clearProperty("app.employee-management.allowed-emails");
            else System.setProperty("app.employee-management.allowed-emails", previousEmployeeAllowlist);
            System.clearProperty("spring.application.json");
            System.clearProperty("spring.datasource.hikari.jdbc-url");
        }
    }

    @Test
    void allowsRecipientAdministrationOnlyWithCompleteSchemaAndStillDisablesMail() {
        var settings = new B4BrowserPreflight.Settings("jdbc:mysql://127.0.0.1:59450/incident_security_disposable",
                "b4_browser_test", "synthetic", "11111111-1111-1111-1111-111111111111", List.of(REPORTER), true);
        var environment = B4BrowserTestServer.isolatedEnvironment(settings);
        assertThat(environment.getProperty("app.notifications.email.recipient-administration.enabled", Boolean.class)).isTrue();
        assertThat(environment.getProperty("app.notifications.email.managed-recipients.enabled", Boolean.class)).isFalse();
        assertThat(environment.getProperty("app.notifications.email.enabled", Boolean.class)).isFalse();
    }

    @Test
    void forwardsExplicitDepartmentAdministrationOptIns() {
        var aliases = java.util.Map.of(
                "APP_DEPARTMENT_HEAD_DESIGNATIONS_ENABLED", "true",
                "APP_HANDLER_ELIGIBILITY_ADMIN_ENABLED", "true",
                "APP_HANDLER_ELIGIBILITY_ADMIN_ALLOWED_EMAILS", "eligibility-admin@example.test");
        var previous = new java.util.HashMap<String, String>();
        aliases.forEach((key, value) -> previous.put(key, System.setProperty(key, value)));
        try {
            var settings = new B4BrowserPreflight.Settings("jdbc:mysql://127.0.0.1:59450/incident_security_disposable",
                    "b4_browser_test", "synthetic", "11111111-1111-1111-1111-111111111111", List.of(REPORTER), false);
            var environment = B4BrowserTestServer.isolatedEnvironment(settings);
            assertThat(environment.getProperty("app.department-head-designations.enabled")).isEqualTo("true");
            assertThat(environment.getProperty("app.handler-eligibility-admin.enabled")).isEqualTo("true");
            assertThat(environment.getProperty("app.handler-eligibility-admin.allowed-emails"))
                    .isEqualTo("eligibility-admin@example.test");
            assertThat(environment.getProperty("app.auth.bootstrap-admin-emails")).isEmpty();
        } finally {
            previous.forEach((key, value) -> {
                if (value == null) System.clearProperty(key);
                else System.setProperty(key, value);
            });
        }
    }

    @Test
    @org.junit.jupiter.api.extension.ExtendWith(org.springframework.boot.test.system.OutputCaptureExtension.class)
    void logsOnlyASafeOAuthFailureCategoryAndKeepsTheRedirect(
            org.springframework.boot.test.system.CapturedOutput output) throws Exception {
        var handler = new B4BrowserTestServer.FixtureAuthenticationFailureHandler();
        var request = new MockHttpServletRequest();
        var response = new MockHttpServletResponse();
        var error = new org.springframework.security.oauth2.core.OAuth2Error(
                "authorization_request_not_found", "synthetic-sensitive-error-detail", null);
        handler.onAuthenticationFailure(request, response,
                new org.springframework.security.oauth2.core.OAuth2AuthenticationException(error));
        assertThat(response.getRedirectedUrl()).isEqualTo("http://127.0.0.1:5175?authError=access_denied");
        assertThat(output.getAll()).contains("B4 Google OAuth callback failed: callback_session_or_state")
                .doesNotContain("synthetic-sensitive-error-detail");
    }

    @Test
    void distinguishesOAuthFailuresWithoutReadingProviderText() {
        var httpFailure = new org.springframework.web.client.HttpServerErrorException(
                org.springframework.http.HttpStatus.BAD_GATEWAY, "synthetic-response-body");
        var transportFailure = new org.springframework.web.client.ResourceAccessException(
                "synthetic-request-url", new javax.net.ssl.SSLHandshakeException("synthetic-tls-detail"));
        assertThat(oauthCategory("invalid_client", null)).isEqualTo("invalid_client_credentials");
        assertThat(oauthCategory("invalid_token_response", httpFailure)).isEqualTo("token_endpoint_http_failure");
        assertThat(oauthCategory("invalid_user_info_response", httpFailure)).isEqualTo("user_info_endpoint_http_failure");
        assertThat(oauthCategory("invalid_user_info_response",
                new org.springframework.security.oauth2.core.OAuth2AuthorizationException(
                        new org.springframework.security.oauth2.core.OAuth2Error("invalid_token"))))
                .isEqualTo("user_info_endpoint_http_failure");
        assertThat(oauthCategory("invalid_id_token", null)).isEqualTo("oidc_other_id_token_validation");
        assertThat(oauthCategory("invalid_user_info_response", null)).isEqualTo("oidc_user_info_subject_validation");
        assertThat(oauthCategory("invalid_token_response", transportFailure)).isEqualTo("token_endpoint_network_or_tls");
        assertThat(oauthCategory("invalid_user_info_response", transportFailure)).isEqualTo("user_info_endpoint_network_or_tls");
        assertThat(oauthCategory("invalid_id_token", transportFailure)).isEqualTo("oidc_validation_network_or_tls");
        assertThat(oauthCategory("invalid_grant", null)).isEqualTo("token_endpoint_grant_rejected");
        assertThat(oauthCategory("synthetic-untrusted-code", null)).isEqualTo("other");
    }

    @Test
    void distinguishesIdTokenChecksUsingSpringSecurityValidationErrors() {
        assertThat(idTokenCategory("The ID Token contains invalid claims: {iss=synthetic-issuer}"))
                .isEqualTo("oidc_issuer_mismatch");
        assertThat(idTokenCategory("The ID Token contains invalid claims: {aud=[synthetic-client]}"))
                .isEqualTo("oidc_audience_or_authorized_party_mismatch");
        assertThat(idTokenCategory("The ID Token contains invalid claims: {azp=synthetic-client}"))
                .isEqualTo("oidc_audience_or_authorized_party_mismatch");
        assertThat(idTokenCategory("The ID Token contains invalid claims: {exp=2026-11-01T00:00:00Z}"))
                .isEqualTo("oidc_token_expired");
        assertThat(idTokenCategory("Jwt used before 2026-11-01T00:00:00Z"))
                .isEqualTo("oidc_nbf_in_future");
        assertThat(idTokenCategory("The ID Token contains invalid claims: {iat=null, sub=null}"))
                .isEqualTo("oidc_required_claim_missing");
        assertThat(idTokenCategory("The ID Token contains invalid claims: {aud=[]}"))
                .isEqualTo("oidc_required_claim_missing");
        assertThat(idTokenCategory("synthetic-unknown-validation-detail"))
                .isEqualTo("oidc_other_claim_validation");
        assertThat(oauthCategory("invalid_id_token", new org.springframework.security.oauth2.jwt.BadJwtException(
                "synthetic-sensitive-token-detail", new com.nimbusds.jose.proc.BadJWSException("synthetic-signature-detail"))))
                .isEqualTo("oidc_signature_or_jwk");
        assertThat(oauthCategory("invalid_nonce", null)).isEqualTo("oidc_nonce_validation");
    }

    @Test
    void identifiesWhichSpringValidatorRejectedAnOidcTimestamp() {
        var now = java.time.Instant.parse("2026-11-10T12:50:00Z");
        var clock = java.time.Clock.fixed(now, java.time.ZoneOffset.UTC);
        var google = org.springframework.security.config.oauth2.client.CommonOAuth2Provider.GOOGLE
                .getBuilder("google").clientId("synthetic-client").clientSecret("synthetic").build();
        var issuedAt = new org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator(google);
        issuedAt.setClock(clock);
        var notBefore = new org.springframework.security.oauth2.jwt.JwtTimestampValidator();
        notBefore.setClock(clock);

        var futureIssued = timestampToken(now, 61, 0);
        assertThat(oidcTimestampFailure(issuedAt.validate(futureIssued))).isEqualTo("oidc_iat_in_future");
        assertThat(notBefore.validate(futureIssued).hasErrors()).isFalse();
        var futureNotBefore = timestampToken(now, 0, 61);
        assertThat(oidcTimestampFailure(notBefore.validate(futureNotBefore))).isEqualTo("oidc_nbf_in_future");
        assertThat(issuedAt.validate(futureNotBefore).hasErrors()).isFalse();
        var atTolerance = timestampToken(now, 60, 60);
        assertThat(issuedAt.validate(atTolerance).hasErrors()).isFalse();
        assertThat(notBefore.validate(atTolerance).hasErrors()).isFalse();
    }

    private static org.springframework.security.oauth2.jwt.Jwt timestampToken(
            java.time.Instant now, int issuedAtSeconds, int notBeforeSeconds) {
        return org.springframework.security.oauth2.jwt.Jwt.withTokenValue("synthetic")
                .header("alg", "RS256").issuer("https://accounts.google.com")
                .subject("synthetic-subject").audience(List.of("synthetic-client"))
                .issuedAt(now.plusSeconds(issuedAtSeconds)).notBefore(now.plusSeconds(notBeforeSeconds))
                .expiresAt(now.plusSeconds(600)).build();
    }

    private static String oidcTimestampFailure(org.springframework.security.oauth2.core.OAuth2TokenValidatorResult result) {
        assertThat(result.hasErrors()).isTrue();
        return oauthCategory("invalid_id_token", new org.springframework.security.oauth2.jwt.JwtValidationException(
                "synthetic validation exception", result.getErrors()));
    }

    private static String idTokenCategory(String description) {
        return oauthCategory("invalid_id_token", new org.springframework.security.oauth2.jwt.JwtValidationException(
                "synthetic-sensitive-token-detail", List.of(new org.springframework.security.oauth2.core.OAuth2Error(
                        "invalid_id_token", description, null))));
    }

    private static String oauthCategory(String code, Throwable cause) {
        var error = new org.springframework.security.oauth2.core.OAuth2Error(code, "synthetic-sensitive-detail", null);
        var failure = cause == null
                ? new org.springframework.security.oauth2.core.OAuth2AuthenticationException(error)
                : new org.springframework.security.oauth2.core.OAuth2AuthenticationException(error, cause);
        return B4BrowserTestServer.FixtureAuthenticationFailureHandler.category(failure);
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
