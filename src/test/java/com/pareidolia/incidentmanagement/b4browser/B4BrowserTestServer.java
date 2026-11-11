package com.pareidolia.incidentmanagement.b4browser;

import com.pareidolia.incidentmanagement.IncidentManagementServiceApplication;
import com.pareidolia.incidentmanagement.security.GoogleAuthenticationFailureHandler;
import com.pareidolia.incidentmanagement.security.GoogleAuthenticationSuccessHandler;
import com.pareidolia.incidentmanagement.security.IncidentAccessPolicy;
import com.pareidolia.incidentmanagement.security.IncidentReadSnapshot;
import com.pareidolia.incidentmanagement.security.IncidentSecurityGate;
import com.pareidolia.incidentmanagement.service.AppUserService;
import com.pareidolia.incidentmanagement.service.EligibleHandlerDirectory;
import com.pareidolia.incidentmanagement.service.IncidentAssignmentService;
import com.pareidolia.incidentmanagement.service.IncidentService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.boot.SpringApplication;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

public final class B4BrowserTestServer {
    private static final String FRONTEND = "http://127.0.0.1:5175";
    private B4BrowserTestServer() { }

    public static void main(String[] args) throws Exception {
        var settings = B4BrowserPreflight.verify(args);
        System.setProperty("spring.devtools.restart.enabled", "false");

        SpringApplication app = new SpringApplication(IncidentManagementServiceApplication.class);
        app.setEnvironment(isolatedEnvironment(settings));
        app.addInitializers(context -> {
            if (!(context instanceof GenericApplicationContext registry)) {
                throw new IllegalStateException("Unexpected B4 browser application context.");
            }
            registry.registerBean("b4FixtureAuthenticationSuccessHandler", GoogleAuthenticationSuccessHandler.class,
                    () -> new FixtureAuthenticationSuccessHandler(context.getBean(AppUserService.class), settings.fixtureEmails()),
                    definition -> definition.setPrimary(true));
            registry.registerBean("b4OAuthFailureHandler", GoogleAuthenticationFailureHandler.class,
                    FixtureAuthenticationFailureHandler::new, definition -> definition.setPrimary(true));
            registry.registerBean("b4BrowserWiringCheck", SmartInitializingSingleton.class, () -> () -> {
                try (var connection = context.getBean(DataSource.class).getConnection()) {
                    if (B4BrowserPreflight.verifyDatabase(connection, settings.serverId()) != settings.managedRecipientSchema()) {
                        throw new IllegalStateException("B4 runtime recipient schema differs from preflight.");
                    }
                } catch (SQLException failure) {
                    throw new IllegalStateException("B4 runtime datasource verification failed.");
                }
                context.getBean(IncidentAssignmentService.class);
                context.getBean(EligibleHandlerDirectory.class);
                var policy = context.getBean(IncidentAccessPolicy.class);
                var gate = context.getBean(IncidentSecurityGate.class);
                var snapshot = context.getBean(IncidentReadSnapshot.class);
                if (!policy.isEnabled() || !context.getBean(IncidentService.class).departmentScopedIntakeAvailable()
                        || !snapshot.read(gate::held) || !context.getBeansOfType(JavaMailSender.class).isEmpty()) {
                    throw new IllegalStateException("B4 browser security wiring or mail isolation could not be verified.");
                }
                System.out.println("B4 browser assignment, policy, gate and snapshot verified. SMTP transport absent.");
            });
        });

        // Test-only exclusion of the startup blocker.
        // IncidentSecurityGate, IncidentAccessPolicy and authorization
        // services remain registered and active.
        app.addInitializers(context ->
                context.addBeanFactoryPostProcessor(factory -> {
                    if (!(factory instanceof BeanDefinitionRegistry registry)) {
                        throw new IllegalStateException(
                                "Unable to verify test bean registry."
                        );
                    }

                    String guardName = "incidentAccessActivationGuard";

                    if (!registry.containsBeanDefinition(guardName)) {
                        throw new IllegalStateException(
                                "Expected B4 activation guard was not found."
                        );
                    }

                    registry.removeBeanDefinition(guardName);
                })
        );

        app.run();
    }

    static StandardEnvironment isolatedEnvironment(B4BrowserPreflight.Settings settings) {
        // Never inherit arbitrary Spring datasource, profile, mail or config overrides.
        var environment = new StandardEnvironment();
        environment.getPropertySources().remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
        environment.getPropertySources().remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
        Map<String, Object> properties = new HashMap<>(Map.ofEntries(
                Map.entry("spring.config.location", "classpath:/application.properties"),
                Map.entry("spring.profiles.active", "dev"),
                Map.entry("spring.datasource.url", settings.url()),
                Map.entry("spring.datasource.username", settings.user()),
                Map.entry("spring.datasource.password", settings.password()),
                Map.entry("server.address", "127.0.0.1"),
                Map.entry("server.port", "18083"),
                Map.entry("spring.jpa.hibernate.ddl-auto", "validate"),
                Map.entry("spring.sql.init.mode", "never"),
                Map.entry("app.incident-access.enabled", "true"),
                Map.entry("app.incident-assignment.enabled", "true"),
                Map.entry("app.employee-management.enabled", "true"),
                Map.entry("app.employee-assignment.active-email-search.enabled", "true"),
                Map.entry(
                        "app.employee-management.allowed-emails",
                        settings.fixtureEmails().get(0)
                ),
                Map.entry("app.auth.bootstrap-admin-emails", ""),
                Map.entry("app.auth.bootstrap-it-handler-emails", ""),
                Map.entry("app.notifications.email.enabled", "false"),
                Map.entry("app.notifications.email.v2.enabled", "false"),
                Map.entry("app.notifications.email.hr-referrals.enabled", "false"),
                Map.entry("app.notifications.email.local-postfix-enabled", "false"),
                Map.entry("app.notifications.email.verified-department-routing.enabled", "false"),
                Map.entry("app.notifications.email.managed-recipients.enabled", "false"),
                Map.entry("app.notifications.email.recipient-administration.enabled", settings.managedRecipientSchema()),
                Map.entry("app.frontend-url", FRONTEND),
                Map.entry("app.cors.allowed-origins", FRONTEND),
                Map.entry("spring.security.oauth2.client.registration.google.redirect-uri",
                        "http://127.0.0.1:18083/login/oauth2/code/google")));
        for (String key : List.of("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "APP_ALLOWED_DOMAIN",
                "INCIDENT_ASSIGNMENT_ALLOWED_PAIRS", "INCIDENT_HR_ACCOUNT_IDS", "INCIDENT_HR_DEPARTMENT_IDS",
                "INCIDENT_TRANSFER_ALLOWED_COORDINATOR_ROUTES", "INCIDENT_TRANSFER_ALLOWED_HANDOFF_REVIEWER_ROUTES",
                "INCIDENT_TRANSFER_HANDOFF_APPROVED", "DEPARTMENT_MEMBERSHIP_ADMIN_ENABLED",
                "DEPARTMENT_MEMBERSHIP_ADMIN_ALLOWED_EMAILS", "app.employee-management.allowed-emails",
                "app.department-head-designations.enabled", "app.handler-eligibility-admin.enabled",
                "app.handler-eligibility-admin.allowed-emails",
                "app.incident-security-admin.enabled", "app.incident-capability-admin.allowed-emails",
                "app.hr-reassignment-referrals.enabled", "app.hr-reassignment-referrals.it-coordinator-ids",
                "app.hr-reassignment-referrals.reviewers.primary-id", "app.hr-reassignment-referrals.reviewers.backup-id")) {
            String value = System.getProperty(key, System.getenv(key));
            if (value != null) properties.put(key, value);
        }
        Map.of("app.department-head-designations.enabled", "APP_DEPARTMENT_HEAD_DESIGNATIONS_ENABLED",
                "app.handler-eligibility-admin.enabled", "APP_HANDLER_ELIGIBILITY_ADMIN_ENABLED",
                "app.handler-eligibility-admin.allowed-emails", "APP_HANDLER_ELIGIBILITY_ADMIN_ALLOWED_EMAILS")
                .forEach((key, alias) -> {
                    String value = System.getProperty(alias, System.getenv(alias));
                    if (value != null) properties.putIfAbsent(key, value);
                });
        environment.getPropertySources().addFirst(new MapPropertySource("b4BrowserIsolation", properties));
        return environment;
    }

    static final class FixtureAuthenticationFailureHandler extends GoogleAuthenticationFailureHandler {
        private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(FixtureAuthenticationFailureHandler.class);

        FixtureAuthenticationFailureHandler() {
            super(FRONTEND);
        }

        @Override
        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                org.springframework.security.core.AuthenticationException failure) throws IOException, ServletException {
            // OAuth exceptions can contain credentials, callback parameters or user information.
            LOG.warn("B4 Google OAuth callback failed: {}", category(failure));
            super.onAuthenticationFailure(request, response, failure);
        }

        static String category(org.springframework.security.core.AuthenticationException failure) {
            if (!(failure instanceof org.springframework.security.oauth2.core.OAuth2AuthenticationException oauthFailure)) {
                return "other";
            }
            String code = oauthFailure.getError().getErrorCode();
            boolean network = false;
            boolean http = false;
            boolean endpointOAuthError = false;
            for (Throwable cause = failure.getCause(); cause != null; cause = cause.getCause()) {
                network |= cause instanceof org.springframework.web.client.ResourceAccessException
                        || cause instanceof javax.net.ssl.SSLException || cause instanceof java.net.SocketException
                        || cause instanceof java.net.UnknownHostException || cause instanceof java.net.SocketTimeoutException
                        || cause instanceof java.net.http.HttpTimeoutException;
                http |= cause instanceof org.springframework.web.client.RestClientResponseException;
                endpointOAuthError |= cause instanceof org.springframework.security.oauth2.core.OAuth2AuthorizationException;
                if (cause.getCause() == cause) break;
            }
            return switch (code) {
                case "invalid_client" -> "invalid_client_credentials";
                case "unauthorized_client" -> "token_endpoint_client_not_authorized";
                case "invalid_grant" -> "token_endpoint_grant_rejected";
                case "invalid_token_response" -> network ? "token_endpoint_network_or_tls"
                        : http ? "token_endpoint_http_failure" : "token_endpoint_response_invalid";
                case "invalid_user_info_response" -> network ? "user_info_endpoint_network_or_tls"
                        : http || endpointOAuthError ? "user_info_endpoint_http_failure"
                        : failure.getCause() == null ? "oidc_user_info_subject_validation" : "user_info_endpoint_response_invalid";
                case "invalid_id_token" -> network ? "oidc_validation_network_or_tls"
                        : http ? "oidc_validation_http_failure"
                        : failure.getCause() == null && oauthFailure.getError().getDescription() != null
                            && oauthFailure.getError().getDescription().startsWith("Missing (required) ID Token in Token Response")
                            ? "oidc_id_token_missing" : idTokenCategory(failure.getCause());
                case "invalid_nonce" -> "oidc_nonce_validation";
                case "missing_signature_verifier" -> "oidc_signature_or_jwk";
                case "invalid_workspace_account" -> "workspace_domain_or_email_verification";
                case "authorization_request_not_found", "invalid_state_parameter" -> "callback_session_or_state";
                case "access_denied" -> "provider_access_denied";
                default -> "other";
            };
        }
        private static String idTokenCategory(Throwable cause) {
            for (; cause != null; cause = cause.getCause()) {
                if (cause instanceof org.springframework.security.oauth2.jwt.JwtValidationException validation) {
                    for (var error : validation.getErrors()) {
                        String description = error.getDescription();
                        if (description == null) continue;
                        if (description.startsWith("Jwt expired at ")) return "oidc_token_expired";
                        if (description.startsWith("Jwt used before ")) return "oidc_nbf_in_future";
                        if (description.equals("exp is required") || description.equals("nbf is required")) {
                            return "oidc_required_claim_missing";
                        }
                        // Spring Security 7.1 reports rejected claim keys and values in one description.
                        // Inspect only the fixed prefix and first key. Never emit the description.
                        var claim = java.util.regex.Pattern.compile(
                                "^The ID Token contains invalid claims: \\{(iss|sub|aud|azp|exp|iat|nbf)=").matcher(description);
                        if (claim.find()) {
                            String key = claim.group(1);
                            String suffix = description.substring(claim.end());
                            if (suffix.matches("(?s)^(?:null|\\[\\]|)(?:, .*|\\})$")) {
                                return "oidc_required_claim_missing";
                            }
                            return switch (key) {
                                case "iss" -> "oidc_issuer_mismatch";
                                case "aud", "azp" -> "oidc_audience_or_authorized_party_mismatch";
                                case "exp" -> "oidc_token_expired";
                                case "iat" -> "oidc_iat_in_future";
                                case "nbf" -> "oidc_nbf_in_future";
                                default -> "oidc_other_claim_validation";
                            };
                        }
                        if (description.equals("The iss claim is not valid")) return "oidc_issuer_mismatch";
                    }
                    return "oidc_other_claim_validation";
                }
                if (cause instanceof com.nimbusds.jose.RemoteKeySourceException
                        || cause instanceof com.nimbusds.jose.proc.BadJWSException
                        || (cause instanceof com.nimbusds.jose.proc.BadJOSEException
                            && "Signed JWT rejected: Another algorithm expected, or no matching key(s) found".equals(cause.getMessage()))) {
                    return "oidc_signature_or_jwk";
                }
                if (cause.getCause() == cause) break;
            }
            return "oidc_other_id_token_validation";
        }

    }

    static final class FixtureAuthenticationSuccessHandler extends GoogleAuthenticationSuccessHandler {
        private final List<String> approvedEmails;

        FixtureAuthenticationSuccessHandler(AppUserService users, List<String> approvedEmails) {
            super(users, FRONTEND);
            this.approvedEmails = approvedEmails;
        }

        @Override
        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                             Authentication authentication) throws IOException, ServletException {
            if (authentication.getPrincipal() instanceof OidcUser oidc && Boolean.TRUE.equals(oidc.getEmailVerified())
                    && approvedEmails.contains(B4BrowserPreflight.normalize(oidc.getEmail()))) {
                super.onAuthenticationSuccess(request, response, authentication);
                return;
            }
            SecurityContextHolder.clearContext();
            var session = request.getSession(false);
            if (session != null) session.invalidate();
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
        }
    }
}
