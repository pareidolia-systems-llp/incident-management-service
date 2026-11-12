package com.pareidolia.incidentmanagement.security;

import com.pareidolia.incidentmanagement.IncidentManagementServiceApplication;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.core.env.MapPropertySource;
import static org.assertj.core.api.Assertions.assertThat;

@EnabledIfEnvironmentVariable(named="V2_SCHEMA_MYSQL_PROOF", matches="true")
class IncidentGuardApplicationMysqlTests {
    private Map<String,Object> configuration() throws Exception {
        String password=System.getenv("V2_SCHEMA_MYSQL_PASSWORD");
        String recipients=System.getenv("V2_READINESS_APPROVED_RECIPIENTS");
        if (password==null || !password.matches("[0-9a-f]{64}") || recipients==null) throw new IllegalStateException("Missing isolated test configuration.");
        String hr=java.util.Arrays.stream(recipients.split(";")).filter(x->x.startsWith("HR=")).findFirst().orElseThrow().substring(3);
        Map<String,Object> p=new HashMap<>();
        p.put("spring.datasource.url","jdbc:mysql://127.0.0.1:59455/incident_v2_runtime_proof_20261112?connectTimeout=5000&socketTimeout=10000&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC");
        p.put("spring.datasource.username","v2_runtime_test");p.put("spring.datasource.password",password);
        p.put("spring.datasource.hikari.pool-name","GuardProofPool");p.put("spring.datasource.hikari.connection-timeout","5000");p.put("spring.datasource.hikari.validation-timeout","1000");
        p.put("spring.jpa.hibernate.ddl-auto","validate");p.put("spring.sql.init.mode","never");
        p.put("server.address","127.0.0.1");p.put("server.port","0");
        p.put("spring.security.oauth2.client.registration.google.client-id","synthetic");p.put("spring.security.oauth2.client.registration.google.client-secret","synthetic");
        p.put("app.auth.allowed-domain","example.test");p.put("app.incident-access.hr-account-ids","1106");p.put("app.incident-access.hr-department-ids","2");
        p.put("app.incident-assignment.allowed-actor-handler-pairs","1:2");
        for(String flag:new String[]{"app.incident-access.enabled","app.incident-assignment.enabled","app.employee-management.enabled","app.employee-management.production-enabled","app.incident-security-admin.enabled","app.department-membership-admin.enabled","app.department-head-designations.enabled","app.handler-eligibility-admin.enabled","app.notifications.email.enabled","app.notifications.email.verified-department-routing.enabled","app.notifications.email.managed-recipients.enabled","app.notifications.email.detailed-department.enabled","app.notifications.email.global-hr-generic.enabled","app.notifications.email.local-postfix-enabled"})p.put(flag,"true");
        for(String name:new String[]{"app.employee-management.allowed-emails","app.department-membership-admin.allowed-emails","app.handler-eligibility-admin.allowed-emails"})p.put(name,"synthetic@example.test");
        p.put("app.notifications.email.verified-department-routing.hr-department-id","2");p.put("app.notifications.email.readiness.approved-recipients",recipients);
        p.put("app.notifications.email.verified-department-routing.restricted-recipients","2="+hr);
        p.put("app.notifications.email.portal-origin","https://portal.example.test");p.put("app.notifications.email.from","alerts@pareidolia.in");
        p.put("app.notifications.email.smtp.host","localhost");p.put("app.notifications.email.smtp.port","25");
        p.put("spring.main.banner-mode","off");p.put("logging.level.root","OFF");
        try(var c=java.sql.DriverManager.getConnection((String)p.get("spring.datasource.url"),"v2_runtime_test",password); var q=c.createStatement(); var rs=q.executeQuery("select @@server_uuid, database(), current_user()")) {
            assertThat(rs.next()).isTrue(); assertThat(rs.getString(1)).isEqualTo("a6563759-ddb5-11f1-9b7c-6e0023da6ea2");
            assertThat(rs.getString(2)).isEqualTo("incident_v2_runtime_proof_20261112"); assertThat(rs.getString(3)).isEqualTo("v2_runtime_test@172.22.0.1");
        }
        return p;
    }
    private org.springframework.context.ConfigurableApplicationContext start(Map<String,Object> p) {
        return new SpringApplicationBuilder(IncidentManagementServiceApplication.class)
                .initializers(c->c.getEnvironment().getPropertySources().addFirst(new MapPropertySource("isolated-proof",p))).run();
    }
    private void rejected(Map<String,Object> p) throws Exception {
        java.util.Set<Long> before=proofThreads();
        try(var monitor=open(p)) {
            long connections=connectionCount(monitor);
            org.assertj.core.api.Assertions.assertThatThrownBy(() -> { try(var ignored=start(p)) { } })
                    .hasStackTraceContaining("Incident access readiness verification failed.");
            long deadline=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(5);
            while(System.nanoTime()<deadline && (connectionCount(monitor)!=connections || !newProofThreads(before).isEmpty())) Thread.sleep(100);
            assertThat(connectionCount(monitor)).isEqualTo(connections);
            assertThat(newProofThreads(before)).isEmpty();
        }
    }
    private long connectionCount(java.sql.Connection c) throws Exception {
        try(var q=c.createStatement();var r=q.executeQuery("select count(*) from information_schema.processlist where user=substring_index(current_user(),'@',1) and db=database()")) { r.next(); return r.getLong(1); }
    }
    private java.util.Set<Long> proofThreads() {
        var ids=new java.util.HashSet<Long>();
        for(var t:Thread.getAllStackTraces().keySet()) if(t.isAlive() && (t.getName().contains("GuardProofPool") || t.getName().startsWith("incident-email-") || t.getName().startsWith("http-nio-") || t.getName().startsWith("Catalina-") || t.getName().startsWith("container-"))) ids.add(t.getId());
        return ids;
    }
    private java.util.Set<Long> newProofThreads(java.util.Set<Long> before) {
        var ids=proofThreads();ids.removeAll(before);return ids;
    }
    @Test void enabledFullApplicationStartsOnVerifiedMysql() throws Exception {
        try(var context=start(configuration())) {
            assertThat(context.isActive()).isTrue();
            assertThat(context.getBean(IncidentAccessActivationGuard.class)).isNotNull();
        }
    }
    @Test void invalidSchemaMetadataRejectsApplicationStartup() throws Exception {
        var p=configuration();
        try(var fault=org.mockito.Mockito.mockStatic(IncidentCriticalSchemaChecks.class)) {
            fault.when(() -> IncidentCriticalSchemaChecks.inspectOnConnection(org.mockito.ArgumentMatchers.any()))
                .thenReturn(IncidentCriticalSchemaChecks.Result.INVALID_SCHEMA);
            rejected(p);
        }
        assertLockAvailable(p);
    }
    @Test void missingRuntimePrivilegeMetadataRejectsApplicationStartup() throws Exception {
        var p=configuration();
        try(var fault=org.mockito.Mockito.mockStatic(IncidentRuntimePrivilegeChecks.class)) {
            fault.when(() -> IncidentRuntimePrivilegeChecks.inspectOnConnection(org.mockito.ArgumentMatchers.any(),org.mockito.ArgumentMatchers.eq(true)))
                .thenReturn(IncidentRuntimePrivilegeChecks.Result.MISSING_PRIVILEGE);
            rejected(p);
        }
        assertLockAvailable(p);
    }
    @Test
    @EnabledIfEnvironmentVariable(named="V2_DENIED_MYSQL_PROOF",matches="true")
    void genuinelyMissingHistoryInsertRejectsApplicationStartup() throws Exception {
        var p=configuration(); String denied=System.getenv("V2_DENIED_MYSQL_PASSWORD");
        if(denied==null || !denied.matches("[0-9a-f]{64}")) throw new IllegalStateException("Missing isolated denied-account credential.");
        p.put("spring.datasource.username","v2_denied_test");p.put("spring.datasource.password",denied);
        try(var c=open(p);var q=c.createStatement();var r=q.executeQuery("select @@server_uuid,database(),current_user(),(select count(*) from information_schema.table_privileges where table_schema=database() and table_name='incident_history' and privilege_type='INSERT' and grantee=concat(char(39),substring_index(current_user(),'@',1),char(39),'@',char(39),substring_index(current_user(),'@',-1),char(39))),(select count(*) from information_schema.column_privileges where table_schema=database() and table_name='incident_history' and privilege_type='INSERT' and grantee=concat(char(39),substring_index(current_user(),'@',1),char(39),'@',char(39),substring_index(current_user(),'@',-1),char(39)))")) {
            assertThat(r.next()).isTrue();assertThat(r.getString(1)).isEqualTo("a6563759-ddb5-11f1-9b7c-6e0023da6ea2");
            assertThat(r.getString(2)).isEqualTo("incident_v2_runtime_proof_20261112");assertThat(r.getString(3)).isEqualTo("v2_denied_test@172.22.0.1");assertThat(r.getLong(4)).isZero();assertThat(r.getLong(5)).isZero();
        }
        rejected(p); assertLockAvailable(p);
    }
    @Test void invalidHrConfigurationRejectsApplicationStartup() throws Exception {
        var p=configuration(); p.put("app.incident-access.hr-department-ids","3");
        rejected(p); assertLockAvailable(p);
    }
    @Test void invalidRecipientConfigurationRejectsApplicationStartup() throws Exception {
        var p=configuration(); p.put("app.notifications.email.verified-department-routing.restricted-recipients","2=not-approved@example.test");
        rejected(p); assertLockAvailable(p);
    }
    @Test void lockContentionRejectsStartupAndReleasesConnections() throws Exception {
        var p=configuration();
        try(var blocker=open(p); var statement=blocker.createStatement()) {
            blocker.setAutoCommit(false);
            try(var rows=statement.executeQuery("select id from incident_security_lock where id=1 for update")) { assertThat(rows.next()).isTrue(); }
            try { rejected(p); } finally { blocker.rollback(); }
        }
        assertLockAvailable(p);
    }
    private java.sql.Connection open(Map<String,Object> p) throws Exception {
        return java.sql.DriverManager.getConnection((String)p.get("spring.datasource.url"),(String)p.get("spring.datasource.username"),(String)p.get("spring.datasource.password"));
    }
    private void assertLockAvailable(Map<String,Object> p) throws Exception {
        try(var c=open(p);var q=c.createStatement()) {
            c.setAutoCommit(false);q.setQueryTimeout(3);
            try(var rows=q.executeQuery("select id from incident_security_lock where id=1 for update")) { assertThat(rows.next()).isTrue(); }
            c.rollback();
        }
    }
}
