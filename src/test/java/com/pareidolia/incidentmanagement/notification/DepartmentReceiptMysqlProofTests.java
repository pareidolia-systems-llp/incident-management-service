package com.pareidolia.incidentmanagement.notification;

import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import static org.assertj.core.api.Assertions.*;

/** Opt-in proof using only new synthetic receipt keys in the isolated MySQL fixture. */
@EnabledIfEnvironmentVariable(named="INCIDENT_NOTIFICATION_MYSQL_PROOF", matches="true")
class DepartmentReceiptMysqlProofTests {
    @EnableTransactionManagement static class Transactions { }

    @Test void independentReceiptsConcurrentClaimsAndUncertainOutcomes() throws Exception {
        String password = System.getenv("INCIDENT_NOTIFICATION_MYSQL_PASSWORD");
        assertThat(password).isNotBlank();
        var ds = new DriverManagerDataSource("jdbc:mysql://127.0.0.1:59455/incident_notification_proof?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC", "notification_test", password);
        var jdbc = new JdbcTemplate(ds);
        assertThat(jdbc.queryForObject("select @@server_uuid", String.class)).isEqualTo("a6563759-ddb5-11f1-9b7c-6e0023da6ea2");
        assertThat(jdbc.queryForObject("select database()", String.class)).isEqualTo("incident_notification_proof");
        assertThat(jdbc.queryForObject("select current_user()", String.class)).isEqualTo("notification_test@172.22.0.1");
        assertThat(jdbc.queryForObject("select count(*) from information_schema.tables where table_schema=database()", Integer.class)).isEqualTo(11); // MySQL exposes only tables this restricted account can access.
        assertThat(jdbc.queryForObject("select count(*) from incident_department_detail_email_receipt where incident_id=2 and recipient_user_id in (1,2,3)", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("select count(*) from incident_department_head_email_receipt where incident_id=2 and recipient_user_id=1", Integer.class)).isZero();
        try (var context = new AnnotationConfigApplicationContext()) {
            context.register(Transactions.class);
            context.registerBean(JdbcTemplate.class, () -> jdbc);
            context.registerBean(DataSourceTransactionManager.class, () -> new DataSourceTransactionManager(ds));
            context.registerBean(DepartmentHeadMailReceipt.class);
            context.registerBean(DepartmentDetailMailReceipt.class);
            context.refresh();
            var generic = context.getBean(DepartmentHeadMailReceipt.class);
            var detail = context.getBean(DepartmentDetailMailReceipt.class);
            generic.claim(2,1); generic.finish(2,1,true);
            detail.claim(2,1); detail.finish(2,1,true);
            assertThat(jdbc.queryForObject("select status from incident_department_head_email_receipt where incident_id=2 and recipient_user_id=1", String.class)).isEqualTo("SENT");
            assertThat(jdbc.queryForObject("select status from incident_department_detail_email_receipt where incident_id=2 and recipient_user_id=1", String.class)).isEqualTo("SENT");
            assertThatThrownBy(() -> detail.claim(2,1)).isInstanceOf(DuplicateKeyException.class);
            detail.claim(2,2); detail.finish(2,2,false);
            assertThat(jdbc.queryForObject("select status from incident_department_detail_email_receipt where incident_id=2 and recipient_user_id=2", String.class)).isEqualTo("UNCERTAIN");
            assertThatThrownBy(() -> detail.claim(2,2)).isInstanceOf(DuplicateKeyException.class);
            var executor = Executors.newFixedThreadPool(2); var start = new CountDownLatch(1);
            try {
                Callable<Boolean> claim = () -> { start.await(); try { detail.claim(2,3); return true; } catch (DuplicateKeyException expected) { return false; } };
                var a = executor.submit(claim); var b = executor.submit(claim); start.countDown();
                assertThat((a.get(20,TimeUnit.SECONDS) ? 1 : 0) + (b.get(20,TimeUnit.SECONDS) ? 1 : 0)).isEqualTo(1);
                assertThat(jdbc.queryForObject("select status from incident_department_detail_email_receipt where incident_id=2 and recipient_user_id=3", String.class)).isEqualTo("CLAIMED");
            } finally { executor.shutdownNow(); }
        }
    }
}
