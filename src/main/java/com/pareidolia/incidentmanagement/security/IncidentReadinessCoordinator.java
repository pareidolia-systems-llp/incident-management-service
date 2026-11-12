package com.pareidolia.incidentmanagement.security;

import com.pareidolia.incidentmanagement.notification.IncidentEmailReadinessChecks;
import com.zaxxer.hikari.HikariDataSource;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/** Synchronous readiness coordinator. The activation guard remains separate. */
public final class IncidentReadinessCoordinator {
    private IncidentReadinessCoordinator() { }
    public enum Result { READY, PRELIMINARY_ONLY, CONFIGURATION_INVALID, SCHEMA_OR_PRIVILEGES_INVALID,
        CASE_OR_HR_INVALID, RECIPIENTS_INVALID, DATABASE_UNAVAILABLE, DEADLINE_EXCEEDED }

    /**
     * Runs on the caller thread: no readiness worker survives a return. The deadline is
     * checked between steps and is not a hard bound on uninterruptible JDBC operations.
     */
    public static Result inspect(Environment environment, HikariDataSource source, JdbcTemplate jdbc,
            ClientRegistration google, JavaMailSender sender, long deadlineMillis) {
        long started=System.nanoTime();
        if (environment == null) return Result.CONFIGURATION_INVALID;
        String domain;
        Set<Long> hrAccounts;
        Set<Long> hrDepartments;
        try {
            domain=environment.getProperty("app.auth.allowed-domain", "").trim();
            hrAccounts=positiveIds(environment.getProperty("app.incident-access.hr-account-ids", ""));
            hrDepartments=positiveIds(environment.getProperty("app.incident-access.hr-department-ids", ""));
            Long emailDepartment=environment.getProperty("app.notifications.email.verified-department-routing.hr-department-id",Long.class);
            if (emailDepartment == null || !hrDepartments.contains(emailDepartment)) return Result.CONFIGURATION_INVALID;
        } catch (RuntimeException failure) { return Result.CONFIGURATION_INVALID; }
        try {
            if (IncidentStartupBoundsChecks.inspect(source,jdbc,deadlineMillis) != IncidentStartupBoundsChecks.Result.CONFIGURED_FOR_FURTHER_CHECKS
                    || IncidentAccessReadinessChecks.inspectV2Dependencies(environment) != IncidentAccessReadinessChecks.Result.READY_FOR_FURTHER_CHECKS
                    || IncidentAccessReadinessChecks.inspectGoogleRegistration(google,domain) != IncidentAccessReadinessChecks.Result.READY_FOR_FURTHER_CHECKS
                    || IncidentEmailReadinessChecks.inspect(environment,sender) != IncidentEmailReadinessChecks.Result.READY_FOR_FURTHER_CHECKS)
                return Result.CONFIGURATION_INVALID;
        } catch (RuntimeException failure) { return Result.CONFIGURATION_INVALID; }
        if (expired(started,deadlineMillis)) return Result.DEADLINE_EXCEEDED;
        try {
            var transaction=new TransactionTemplate(new DataSourceTransactionManager(source));
            transaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
            transaction.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
            transaction.setTimeout((int)Math.min(jdbc.getQueryTimeout(),Math.max(1,TimeUnit.MILLISECONDS.toSeconds(deadlineMillis))));
            Result result=transaction.execute(status -> {
                try {
                    if (expired(started,deadlineMillis)) return Result.DEADLINE_EXCEEDED;
                    Long id=jdbc.queryForObject("select id from incident_security_lock where id=1 for update",Long.class);
                    if (!Long.valueOf(1).equals(id)) return Result.SCHEMA_OR_PRIVILEGES_INVALID;
                    if (expired(started,deadlineMillis)) return Result.DEADLINE_EXCEEDED;
                    var schema=IncidentCriticalSchemaChecks.inspectOnConnection(jdbc);
                    if (schema == IncidentCriticalSchemaChecks.Result.UNAVAILABLE) return Result.DATABASE_UNAVAILABLE;
                    if (schema != IncidentCriticalSchemaChecks.Result.VERIFIED_FOR_FURTHER_CHECKS) return Result.SCHEMA_OR_PRIVILEGES_INVALID;
                    var privileges=IncidentRuntimePrivilegeChecks.inspectOnConnection(jdbc,true);
                    if (privileges == IncidentRuntimePrivilegeChecks.Result.UNAVAILABLE) return Result.DATABASE_UNAVAILABLE;
                    if (privileges != IncidentRuntimePrivilegeChecks.Result.VERIFIED_FOR_FURTHER_CHECKS) return Result.SCHEMA_OR_PRIVILEGES_INVALID;
                    if (expired(started,deadlineMillis)) return Result.DEADLINE_EXCEEDED;
                    var caseReadiness=IncidentAccessReadinessChecks.inspect(jdbc,hrAccounts,domain);
                    if (caseReadiness == IncidentAccessReadinessChecks.Result.UNAVAILABLE) return Result.DATABASE_UNAVAILABLE;
                    if (caseReadiness != IncidentAccessReadinessChecks.Result.READY_FOR_FURTHER_CHECKS) return Result.CASE_OR_HR_INVALID;
                    if (expired(started,deadlineMillis)) return Result.DEADLINE_EXCEEDED;
                    var hrDepartmentsReady=IncidentAccessReadinessChecks.inspectHrDepartments(jdbc,hrDepartments);
                    if (hrDepartmentsReady == IncidentAccessReadinessChecks.Result.UNAVAILABLE) return Result.DATABASE_UNAVAILABLE;
                    if (hrDepartmentsReady != IncidentAccessReadinessChecks.Result.READY_FOR_FURTHER_CHECKS) return Result.CASE_OR_HR_INVALID;
                    var recipients=IncidentRecipientReadinessChecks.inspectOnConnection(jdbc,environment);
                    if (recipients == IncidentRecipientReadinessChecks.Result.UNAVAILABLE) return Result.DATABASE_UNAVAILABLE;
                    if (recipients != IncidentRecipientReadinessChecks.Result.READY_FOR_FURTHER_CHECKS) return Result.RECIPIENTS_INVALID;
                    if (expired(started,deadlineMillis)) return Result.DEADLINE_EXCEEDED;
                    return Result.READY;
                } finally { status.setRollbackOnly(); }
            });
            if (expired(started,deadlineMillis)) return Result.DEADLINE_EXCEEDED;
            return result == null ? Result.DATABASE_UNAVAILABLE : result;
        } catch (RuntimeException failure) {
            return expired(started,deadlineMillis) ? Result.DEADLINE_EXCEEDED : Result.DATABASE_UNAVAILABLE;
        }
    }
    private static boolean expired(long started,long deadlineMillis) {
        return System.nanoTime()-started >= TimeUnit.MILLISECONDS.toNanos(deadlineMillis);
    }
    private static Set<Long> positiveIds(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException();
        var ids=new java.util.HashSet<Long>();
        for (String part:value.split(",",-1)) {
            String trimmed=part.trim();
            if (!trimmed.matches("[1-9][0-9]*") || !ids.add(Long.parseLong(trimmed))) throw new IllegalArgumentException();
        }
        return Set.copyOf(ids);
    }
}
