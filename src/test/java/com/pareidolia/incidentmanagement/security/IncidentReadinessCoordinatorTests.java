package com.pareidolia.incidentmanagement.security;

import com.zaxxer.hikari.HikariDataSource;
import java.sql.SQLException;
import java.util.Properties;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class IncidentReadinessCoordinatorTests {
    HikariDataSource source; JdbcTemplate jdbc; MockEnvironment env; ClientRegistration google; JavaMailSenderImpl sender;
    @BeforeEach void setup() {
        source=mock(HikariDataSource.class);
        when(source.getConnectionTimeout()).thenReturn(1000L); when(source.getValidationTimeout()).thenReturn(500L);
        when(source.getJdbcUrl()).thenReturn("jdbc:mysql://127.0.0.1:59455/synthetic?connectTimeout=1000&socketTimeout=1000");
        when(source.getDataSourceProperties()).thenReturn(new Properties());
        jdbc=new JdbcTemplate(source);jdbc.setQueryTimeout(1);
        env=new MockEnvironment();
        for(String flag:new String[]{"app.incident-access.enabled","app.incident-assignment.enabled","app.employee-management.enabled",
                "app.employee-management.production-enabled","app.incident-security-admin.enabled","app.department-membership-admin.enabled",
                "app.department-head-designations.enabled","app.handler-eligibility-admin.enabled","app.notifications.email.enabled",
                "app.notifications.email.verified-department-routing.enabled","app.notifications.email.managed-recipients.enabled",
                "app.notifications.email.detailed-department.enabled","app.notifications.email.global-hr-generic.enabled","app.notifications.email.local-postfix-enabled"}) env.setProperty(flag,"true");
        env.setProperty("spring.jpa.hibernate.ddl-auto","validate");env.setProperty("spring.sql.init.mode","never");
        env.setProperty("app.employee-management.allowed-emails","synthetic@example.test");
        env.setProperty("app.department-membership-admin.allowed-emails","synthetic@example.test");env.setProperty("app.handler-eligibility-admin.allowed-emails","synthetic@example.test");
        env.setProperty("app.incident-access.hr-account-ids","1");env.setProperty("app.incident-access.hr-department-ids","2");
        env.setProperty("app.auth.allowed-domain","example.test");
        env.setProperty("app.incident-assignment.allowed-actor-handler-pairs","1:2");
        env.setProperty("app.notifications.email.verified-department-routing.hr-department-id","2");
        env.setProperty("app.notifications.email.portal-origin","https://portal.example.test");env.setProperty("app.notifications.email.from","alerts@pareidolia.in");
        google=CommonOAuth2Provider.GOOGLE.getBuilder("google").clientId("synthetic").clientSecret("synthetic").build();
        sender=new JavaMailSenderImpl();sender.setHost("localhost");sender.setPort(25);
    }
    @Test void missingFeatureFailsBeforeAcquiringAConnection() throws Exception {
        env.setProperty("app.incident-security-admin.enabled","false");
        assertThat(IncidentReadinessCoordinator.inspect(env,source,jdbc,google,sender,10000)).isEqualTo(IncidentReadinessCoordinator.Result.CONFIGURATION_INVALID);
        verify(source,never()).getConnection();
    }
    @Test void databaseConnectionFailureIsSanitizedAndRepeatedEvaluationRemainsClosed() throws Exception {
        when(source.getConnection()).thenThrow(new SQLException("sensitive synthetic driver detail"));
        for(int i=0;i<2;i++) assertThat(IncidentReadinessCoordinator.inspect(env,source,jdbc,google,sender,10000)).isEqualTo(IncidentReadinessCoordinator.Result.DATABASE_UNAVAILABLE);
        verify(source,times(2)).getConnection();
    }
    @Test void invalidOauthFailsWithoutDatabaseAccess() throws Exception {
        assertThat(IncidentReadinessCoordinator.inspect(env,source,jdbc,null,sender,10000)).isEqualTo(IncidentReadinessCoordinator.Result.CONFIGURATION_INVALID);
        verify(source,never()).getConnection();
    }
    @Test void elapsedDeadlineFailsBeforeDatabaseAndDoesNotSpawnAWorker() throws Exception {
        var slow=spy(env);
        doAnswer(call->{java.util.concurrent.locks.LockSupport.parkNanos(java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(1100));return call.callRealMethod();})
                .when(slow).getProperty("app.incident-access.enabled",Boolean.class,false);
        assertThat(IncidentReadinessCoordinator.inspect(slow,source,jdbc,google,sender,1000))
                .isEqualTo(IncidentReadinessCoordinator.Result.DEADLINE_EXCEEDED);
        verify(source,never()).getConnection();
    }
    @Test void inconsistentHrConfigurationFailsBeforeDatabaseAccess() throws Exception {
        env.setProperty("app.notifications.email.verified-department-routing.hr-department-id","3");
        assertThat(IncidentReadinessCoordinator.inspect(env,source,jdbc,google,sender,10000)).isEqualTo(IncidentReadinessCoordinator.Result.CONFIGURATION_INVALID);
        verify(source,never()).getConnection();
    }
    @Test void unexpectedConfigurationFailureReturnsOnlyCategory() throws Exception {
        var broken=mock(ClientRegistration.class);
        when(broken.getRegistrationId()).thenReturn("google");
        when(broken.getClientId()).thenThrow(new IllegalStateException("synthetic confidential detail"));
        assertThat(IncidentReadinessCoordinator.inspect(env,source,jdbc,broken,sender,10000))
                .isEqualTo(IncidentReadinessCoordinator.Result.CONFIGURATION_INVALID);
        verify(source,never()).getConnection();
    }
}
