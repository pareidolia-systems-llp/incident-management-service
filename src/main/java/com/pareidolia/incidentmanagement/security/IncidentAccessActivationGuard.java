package com.pareidolia.incidentmanagement.security;

import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Component;

/** Fail-closed startup gate. JDBC deadlines cannot interrupt every driver operation. */
@Component
@Lazy(false)
public class IncidentAccessActivationGuard {
    /** Compatibility entry point: it never permits enabled activation without readiness. */
    public IncidentAccessActivationGuard(boolean enabled) {
        if (enabled) throw new IllegalStateException("Incident access readiness unavailable.");
    }

    @Autowired
    public IncidentAccessActivationGuard(@Value("${app.incident-access.enabled:false}") boolean enabled,
            Environment environment, ObjectProvider<HikariDataSource> sources,
            ObjectProvider<ClientRegistrationRepository> registrations,
            ObjectProvider<JavaMailSender> senders) {
        if (!enabled) return;
        try {
            HikariDataSource source=sources.getIfUnique();
            ClientRegistrationRepository repository=registrations.getIfUnique();
            JavaMailSender sender=senders.getIfUnique();
            if (source == null || repository == null || sender == null) throw new IllegalStateException();
            var jdbc=new JdbcTemplate(source);
            jdbc.setQueryTimeout(2);
            var result=IncidentReadinessCoordinator.inspect(environment,source,jdbc,
                    repository.findByRegistrationId("google"),sender,10000);
            if (result != IncidentReadinessCoordinator.Result.READY) throw new IllegalStateException();
        } catch (RuntimeException failure) {
            throw new IllegalStateException("Incident access readiness verification failed.");
        }
    }
}
