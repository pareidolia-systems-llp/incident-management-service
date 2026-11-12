package com.pareidolia.incidentmanagement.security;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import static org.assertj.core.api.Assertions.assertThat;

class IncidentActivationGuardContextTests {
    @Test void disabledGuardDoesNotRequireReadinessDependencies() {
        new ApplicationContextRunner().withUserConfiguration(IncidentAccessActivationGuard.class)
            .run(context -> assertThat(context).hasNotFailed());
    }
    @Test void enabledGuardFailsWhenDependenciesAreMissing() {
        new ApplicationContextRunner().withUserConfiguration(IncidentAccessActivationGuard.class)
            .withPropertyValues("app.incident-access.enabled=true")
            .run(context -> assertThat(context).hasFailed());
    }
}
