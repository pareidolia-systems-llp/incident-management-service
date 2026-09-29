# Railway deployment configuration

This Spring Boot application builds an executable JAR with Maven. Railway supplies the runtime `PORT`; do not set a fixed production port in Railway.

Configure these Railway variables before deploying:

| Variable | Purpose | Example format |
| --- | --- | --- |
| `DB_URL` | JDBC connection URL for the Railway MySQL database | `jdbc:mysql://<host>:<port>/<database>` |
| `DB_USER` | MySQL database username | `<database-user>` |
| `DB_PASS` | MySQL database password | `<database-password>` |
| `CORS_ALLOWED_ORIGINS` | Comma-separated frontend origins allowed to call `/api/**` | `https://<frontend-host>` |
| `JPA_DDL_AUTO` | Hibernate schema management mode | `update` or `validate` |
| `JPA_SHOW_SQL` | Enables Hibernate SQL logging when set to `true` | `false` |

`CORS_ALLOWED_ORIGINS` defaults to `http://localhost:5173` for local development. Set it to the deployed frontend origin in Railway; do not use `*`.

For a production deployment, use `JPA_SHOW_SQL=false`. Choose `JPA_DDL_AUTO` according to the database-management policy; the local default remains `update`.
