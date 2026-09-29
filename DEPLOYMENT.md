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
| `GOOGLE_CLIENT_ID` | Google OAuth 2.0 web application client ID | `<google-client-id>` |
| `GOOGLE_CLIENT_SECRET` | Google OAuth 2.0 web application client secret | `<google-client-secret>` |
| `APP_ALLOWED_DOMAIN` | Required Google Workspace hosted domain | `pareidolia.in` |
| `APP_FRONTEND_URL` | Frontend URL used after successful Google login | `http://localhost:5173` |
| `APP_BOOTSTRAP_ADMIN_EMAILS` | Comma-separated emails to provision as administrators | `<admin-email>` |
| `SESSION_COOKIE_SAME_SITE` | Session cookie SameSite policy | `Lax` or `None` |
| `SESSION_COOKIE_SECURE` | Requires HTTPS for the session cookie when set to `true` | `false` |

`CORS_ALLOWED_ORIGINS` defaults to `http://localhost:5173` for local development. Set it to the deployed frontend origin in Railway; do not use `*`.

For a production deployment, use `JPA_SHOW_SQL=false`. Choose `JPA_DDL_AUTO` according to the database-management policy; the local default remains `update`.

Google OAuth uses only `openid`, `profile`, and `email` scopes. Register the deployed backend callback URI with Google before deployment. For a cross-site HTTPS frontend, use `SESSION_COOKIE_SAME_SITE=None` and `SESSION_COOKIE_SECURE=true`.
