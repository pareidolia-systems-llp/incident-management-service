# Managed-recipient readiness diagnostic

The diagnostic reads `app.notifications.email.readiness.approved-recipients`, a deployment-controlled allowlist. This is an additional readiness check and does not grant case access, employee roles or department memberships. The production activation guard remains separate.

Example using synthetic addresses only:

```properties
app.notifications.email.readiness.approved-recipients=IT=it@example.test;HR=hr@example.test;Operations (Annotation)=annotation@example.test;Operations (Perioperative Flow Analysis)=perioperative@example.test;R&D=research@example.test
```

Each required department must have an active managed-recipient row that matches an approved address and an active application account with an active matching membership without requiring a previous login. The sender still requires a prior login timestamp at dispatch; until that happens no notification is sent. A timestamp is not proof of an immutable Google identity. Active managed recipients outside the allowlist are rejected. Case-level VIEW and HR confidentiality remain dispatch-time checks.

The allowlist must be reviewed against the current approved routing policy and set in deployment configuration. An administrator must review changes; adding an address to the allowlist does not make its account authorized for any incident. The configured restricted-recipient matrix must contain an approved active HR recipient; each configured entry must identify an active department and approved active managed recipients. This diagnostic does not validate SMTP delivery, current Google Console settings or future case grants.
