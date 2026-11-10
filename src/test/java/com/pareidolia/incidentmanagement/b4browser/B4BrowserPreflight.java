package com.pareidolia.incidentmanagement.b4browser;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

public final class B4BrowserPreflight {
    private static final String DATABASE = "incident_security_disposable";
    private static final String DATABASE_USER = "b4_browser_test";

    private B4BrowserPreflight() { }

    public static void main(String[] args) throws SQLException {
        verify(args);
        System.out.println("B4 isolated database and fixture ownership verified.");
    }

    record Settings(String url, String user, String password, String serverId, List<String> fixtureEmails) {
        @Override public String toString() { return "B4 browser preflight settings [redacted]"; }
    }

    static Settings verify(String[] args) throws SQLException {
        if (args.length != 0) throw new IllegalStateException("B4 browser testing does not accept arguments.");

        String url = System.getenv("B4_TEST_DATABASE_URL");
        String user = System.getenv("B4_TEST_DATABASE_USER");
        String password = System.getenv("B4_TEST_DATABASE_PASSWORD");
        String serverId = System.getenv("B4_TEST_DATABASE_SERVER_UUID");
        List<String> emails = fixtureEmails(System.getenv("B4_TEST_ALLOWED_EMAIL"));

        if (url == null || !url.matches("jdbc:mysql://127\\.0\\.0\\.1:[0-9]{4,5}/" + DATABASE)) {
            throw new IllegalStateException("B4 browser testing requires the loopback-only disposable database URL.");
        }
        if (!DATABASE_USER.equals(user) || password == null || password.isBlank()) {
            throw new IllegalStateException("Dedicated B4 test database credentials are required.");
        }
        if (serverId == null || !serverId.matches("(?i)[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}")) {
            throw new IllegalStateException("Set B4_TEST_DATABASE_SERVER_UUID from the independently verified disposable MySQL server.");
        }

        try (var connection = DriverManager.getConnection(url, user, password)) {
            verifyDatabase(connection, serverId);
            verifyFixtureOwnership(connection, emails);
        }
        return new Settings(url, user, password, serverId, emails);
    }

    static List<String> fixtureEmails(String input) {
        if (input == null) throw new IllegalStateException("Set B4_TEST_ALLOWED_EMAIL to approved fixture accounts.");
        var emails = Arrays.stream(input.split(",", -1)).map(B4BrowserPreflight::normalize).distinct().toList();
        if (emails.stream().anyMatch(email -> !email.matches("[^\\s@]+@[^\\s@]+\\.[^\\s@]+"))) {
            throw new IllegalStateException("B4_TEST_ALLOWED_EMAIL must contain approved fixture email addresses.");
        }
        return emails;
    }

    static String normalize(String email) {
        return email == null ? "" : email.strip().toLowerCase(Locale.ROOT);
    }

    static void verifyDatabase(Connection connection, String expectedServerId) throws SQLException {
        if (connection.isReadOnly()) throw new IllegalStateException("Unexpected read-only B4 test connection.");
        try (var statement = connection.createStatement();
             var result = statement.executeQuery("""
                     SELECT DATABASE(), @@server_uuid, VERSION(), SUBSTRING_INDEX(CURRENT_USER(), '@', 1),
                            (SELECT COUNT(*) FROM information_schema.tables
                               WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'),
                            (SELECT COUNT(*) FROM incident_security_lock WHERE id = 1),
                            (SELECT COUNT(*) FROM incident_security_lock)
                     """)) {
            if (!result.next() || !DATABASE.equals(result.getString(1))
                    || !expectedServerId.equalsIgnoreCase(result.getString(2))
                    || !result.getString(3).startsWith("8.4.") || !DATABASE_USER.equals(result.getString(4))
                    || result.getInt(5) != 32 || result.getInt(6) != 1 || result.getInt(7) != 1 || result.next()) {
                throw new IllegalStateException("B4 disposable database identity or schema verification failed.");
            }
        }
    }

    static void verifyFixtureOwnership(Connection connection, List<String> approvedEmails) throws SQLException {
        String bind = String.join(", ", Collections.nCopies(approvedEmails.size(), "?"));
        String sql = """
                SELECT
                  (SELECT COUNT(*) FROM app_users
                    WHERE email IS NULL OR LOWER(TRIM(email)) NOT IN (%1$s)),
                  (SELECT COUNT(*) FROM incidents i
                    WHERE i.reported_by IS NULL OR LOWER(TRIM(i.reported_by)) NOT IN (%1$s)
                       OR i.incident_number IS NULL
                       OR NOT REGEXP_LIKE(i.incident_number, '^INC-[0-9]{8}-[0-9]{6}-[A-F0-9]{8}$')
                       OR NOT EXISTS (SELECT 1 FROM app_users u
                                       WHERE LOWER(TRIM(u.email)) = LOWER(TRIM(i.reported_by)))
                       OR NOT EXISTS (SELECT 1 FROM incident_history h WHERE h.incident_id = i.id
                                       AND h.action_type = 'INCIDENT_CREATED'
                                       AND LOWER(TRIM(h.changed_by)) = LOWER(TRIM(i.reported_by))))
                """.formatted(bind);
        try (var statement = connection.prepareStatement(sql)) {
            int parameter = 1;
            for (String email : approvedEmails) statement.setString(parameter++, email);
            for (String email : approvedEmails) statement.setString(parameter++, email);
            try (var result = statement.executeQuery()) {
                if (!result.next() || result.getLong(1) != 0 || result.getLong(2) != 0 || result.next()) {
                    throw new IllegalStateException("Database contains an unapproved account or an incident without matching fixture ownership.");
                }
            }
        }
    }
}
