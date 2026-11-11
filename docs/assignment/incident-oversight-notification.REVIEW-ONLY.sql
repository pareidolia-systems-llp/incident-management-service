-- REVIEW ONLY. Requires existing InnoDB incidents and app_users with signed BIGINT keys.
-- Treat notification rows as append-only audit evidence. Do not backfill historical incidents.
CREATE TABLE incident_oversight_notification (
    id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    incident_id BIGINT NOT NULL,
    recipient_user_id BIGINT NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uk_oversight_incident_recipient (incident_id, recipient_user_id),
    KEY idx_oversight_inbox (recipient_user_id, created_at, id),
    CONSTRAINT fk_oversight_incident FOREIGN KEY (incident_id) REFERENCES incidents(id),
    CONSTRAINT fk_oversight_recipient FOREIGN KEY (recipient_user_id) REFERENCES app_users(id)
) ENGINE=InnoDB;
