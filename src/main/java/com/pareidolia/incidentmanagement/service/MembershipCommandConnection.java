package com.pareidolia.incidentmanagement.service;

import com.pareidolia.incidentmanagement.security.IncidentSecurityGate;
import java.util.function.ToLongFunction;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.support.JdbcTransactionManager;
import org.springframework.stereotype.Component;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/** The dedicated data source and manager are private to membership commands. */
@Component
@ConditionalOnProperty(prefix = "app.department-membership-admin", name = {"enabled", "dedicated-command.enabled"},
        havingValue = "true")
class MembershipCommandConnection {
    private static final String IDENTITY_SQL = "select @@server_uuid, database(), current_user()";

    private final JdbcClient jdbc;
    private final TransactionTemplate transaction;
    private final DatabaseIdentity identity;

    MembershipCommandConnection(DataSource ordinary,
            @Value("${app.department-membership-admin.dedicated-command.url:}") String url,
            @Value("${app.department-membership-admin.dedicated-command.username:}") String username,
            @Value("${app.department-membership-admin.dedicated-command.password:}") String password) {
        if (!url.startsWith("jdbc:mysql://") || username.isBlank() || password.isBlank()) {
            throw new IllegalStateException("Dedicated membership command requires explicit MySQL connection settings.");
        }
        var source = new DriverManagerDataSource(url, username, password);
        jdbc = JdbcClient.create(source);
        transaction = new TransactionTemplate(new JdbcTransactionManager(source));
        transaction.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
        transaction.setTimeout(15);

        var ordinaryIdentity = identify(JdbcClient.create(ordinary));
        identity = identify(jdbc);
        if (!ordinaryIdentity.server().equals(identity.server()) || !ordinaryIdentity.schema().equals(identity.schema())
                || !identity.username().equals(username) || ordinaryIdentity.username().equals(identity.username())) {
            throw new IllegalStateException("Membership command requires a distinct MySQL user on the ordinary server and schema.");
        }
    }

    long execute(ToLongFunction<JdbcClient> command) {
        if (TransactionSynchronizationManager.isActualTransactionActive()
                || TransactionSynchronizationManager.isSynchronizationActive()) {
            throw new IllegalStateException("Membership command must own its transaction.");
        }
        return transaction.execute(status -> {
            if (!identity.equals(identify(jdbc))) {
                throw new IllegalStateException("Membership command database identity changed.");
            }
            if (jdbc.sql(IncidentSecurityGate.EXCLUSIVE_LOCK_SQL).query(Long.class).list().size() != 1) {
                throw new IllegalStateException("Incident security lock migration is missing.");
            }
            return command.applyAsLong(jdbc);
        });
    }

    private static DatabaseIdentity identify(JdbcClient connection) {
        return connection.sql(IDENTITY_SQL).query((row, index) -> {
            String account = row.getString(3);
            String schema = row.getString(2);
            if (schema == null || account == null || account.lastIndexOf('@') < 1) {
                throw new IllegalStateException("Membership command database identity could not be verified.");
            }
            return new DatabaseIdentity(row.getString(1), schema, account);
        }).single();
    }

    private record DatabaseIdentity(String server, String schema, String account) {
        String username() {
            return account.substring(0, account.lastIndexOf('@'));
        }
    }
}
