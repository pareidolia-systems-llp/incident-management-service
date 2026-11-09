package com.pareidolia.incidentmanagement;

import org.springframework.test.context.DynamicPropertyRegistry;
import java.sql.DriverManager;
import java.sql.SQLException;

/** Validate the fresh container before Hibernate or test fixtures may write anything. */
final class DisposableAssignmentDatabase {
    private static final String PREFIX = "INCIDENT_SECURITY_DISPOSABLE_MYSQL_";

    static boolean mysql() {
        String url = System.getenv(PREFIX + "URL");
        return url != null && !url.isBlank();
    }

    static void configure(DynamicPropertyRegistry properties, String memoryName) {
        String url = System.getenv(PREFIX + "URL");
        String password = System.getenv(PREFIX + "PASSWORD");
        if (!mysql() && "true".equals(System.getenv(PREFIX + "APPROVED"))) {
            throw new IllegalStateException("Approved MySQL run requires its disposable JDBC URL.");
        }
        if (mysql()) {
            String token = System.getenv(PREFIX + "TOKEN");
            if (!"true".equals(System.getenv(PREFIX + "APPROVED")) || token == null
                    || !token.matches("[0-9a-f]{32}") || password == null || !password.matches("[0-9a-f]{64}")
                    || !url.matches("jdbc:mysql://127\\.0\\.0\\.1:[0-9]{4,5}/incident_security_disposable\\?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC")) {
                throw new IllegalStateException("Invalid disposable database configuration.");
            }
            try (var connection = DriverManager.getConnection(url, "security_test", password);
                 var query = connection.prepareStatement("select database(),version(),(select count(*) from information_schema.tables where table_schema=database()),token from disposable_run_marker");
                 var rows = query.executeQuery()) {
                if (!rows.next() || !"incident_security_disposable".equals(rows.getString(1))
                        || !rows.getString(2).startsWith("8.4.") || rows.getInt(3) != 1
                        || !token.equals(rows.getString(4)) || rows.next()) {
                    throw new IllegalStateException("Expected the empty, newly marked MySQL 8.4 schema.");
                }
            } catch (SQLException ex) {
                throw new IllegalStateException("Disposable database identity check failed.", ex);
            }
        }
        properties.add("spring.datasource.url", () -> mysql() ? url : "jdbc:h2:mem:" + memoryName + ";MODE=MySQL;DB_CLOSE_DELAY=-1");
        properties.add("spring.datasource.username", () -> mysql() ? "security_test" : "sa");
        properties.add("spring.datasource.password", () -> mysql() ? password : "");
        properties.add("spring.jpa.hibernate.ddl-auto", () -> mysql() ? "update" : "create-drop");
        properties.add("spring.jpa.show-sql", () -> "false");
    }
}
