# B4 notification configuration

Both review-only migrations require existing InnoDB incidents and app_users tables with matching signed BIGINT keys. Apply them only after a separate migration review. No historical notification rows are seeded.

## Department-head email

- Use the existing master mail, verified routing and department-head opt-ins. Set the existing department-head recipient matrix to the exact approved addresses per department. Use the existing restricted-recipient matrix and HR scope for restricted cases.
- Set app.notifications.email.verified-department-routing.department-head-notifications.rollout-cutoff to an ISO local datetime in the same application timezone as incidents.created_at. Only strictly later incidents qualify. Use a forward cutoff when adopting the receipt so earlier mail with no receipt is not replayed.
- Configure the approved HTTPS portal origin and keep the existing DEV allowlist and transport controls. Keep SMTP disabled in localhost. Test via capture or mocks.
- A successful SMTP submission records SENT. UNCERTAIN and unfinalized CLAIMED rows are never automatically replayed. A crash can occur between the durable claim, SMTP acceptance and final status write. Reconcile transport evidence before any manual replay.

## Oversight inbox

- Set app.notifications.oversight.enabled, app.notifications.oversight.it-user-id and app.notifications.oversight.hr-user-id only after verifying the approved active app-user IDs. The IDs must be distinct. No case grants are created.
- The frontend uses VITE_INCIDENT_OVERSIGHT_ENABLED. The dashboard lists only generic notices addressed to the signed-in account. Opening a notice independently checks ownership and current case visibility.
