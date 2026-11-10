package com.pareidolia.incidentmanagement.b4browser;

import com.pareidolia.incidentmanagement.IncidentManagementServiceApplication;
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
            registry.registerBean("b4BrowserWiringCheck", SmartInitializingSingleton.class, () -> () -> {
                try (var connection = context.getBean(DataSource.class).getConnection()) {
                    B4BrowserPreflight.verifyDatabase(connection, settings.serverId());
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
                Map.entry("app.auth.bootstrap-admin-emails", ""),
                Map.entry("app.auth.bootstrap-it-handler-emails", ""),
                Map.entry("app.notifications.email.enabled", "false"),
                Map.entry("app.notifications.email.v2.enabled", "false"),
                Map.entry("app.notifications.email.hr-referrals.enabled", "false"),
                Map.entry("app.notifications.email.local-postfix-enabled", "false"),
                Map.entry("app.notifications.email.verified-department-routing.enabled", "false"),
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
                "app.incident-security-admin.enabled", "app.incident-capability-admin.allowed-emails",
                "app.hr-reassignment-referrals.enabled", "app.hr-reassignment-referrals.it-coordinator-ids",
                "app.hr-reassignment-referrals.reviewers.primary-id", "app.hr-reassignment-referrals.reviewers.backup-id")) {
            String value = System.getProperty(key, System.getenv(key));
            if (value != null) properties.put(key, value);
        }
        environment.getPropertySources().addFirst(new MapPropertySource("b4BrowserIsolation", properties));
        return environment;
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
