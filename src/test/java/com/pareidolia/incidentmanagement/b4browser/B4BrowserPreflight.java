
package com.pareidolia.incidentmanagement.b4browser;



import java.sql.DriverManager;

public class B4BrowserPreflight {

    public static void main(String[] args) throws Exception {

        String url = System.getenv("B4_TEST_DATABASE_URL");
        String user = System.getenv("B4_TEST_DATABASE_USER");
        String password = System.getenv("B4_TEST_DATABASE_PASSWORD");

        if (url == null || !url.matches(
                "jdbc:mysql://127\\.0\\.0\\.1:[0-9]{4,5}/incident_security_disposable"
        )) {
            throw new IllegalStateException(
                    "B4 browser testing requires the isolated disposable database."
            );
        }

        if (user == null || password == null || password.isBlank()) {
            throw new IllegalStateException(
                    "Dedicated test database credentials are required."
            );
        }

        try (var connection = DriverManager.getConnection(url, user, password);
             var statement = connection.createStatement()) {

            try (var result = statement.executeQuery("""
                SELECT DATABASE(),
                       (SELECT COUNT(*)
                          FROM information_schema.tables
                         WHERE table_schema = DATABASE()
                           AND table_type = 'BASE TABLE'),
                       (SELECT COUNT(*) FROM app_users),
                       (SELECT COUNT(*) FROM incidents),
                       (SELECT COUNT(*) FROM incident_security_lock
                         WHERE id = 1)
                """)) {

                if (!result.next()
                        || !"incident_security_disposable".equals(result.getString(1))
                        || result.getInt(2) != 32
                        || result.getInt(3) != 0
                        || result.getInt(4) != 0
                        || result.getInt(5) != 1) {
                    throw new IllegalStateException(
                            "B4 disposable database verification failed."
                    );
                }
            }
        }

        System.out.println("B4 isolated database preflight passed.");
        System.out.println("Browser test application not started yet.");
    }
}
