-- REVIEW ONLY. Verify existing signed BIGINT keys and InnoDB tables before approval.
-- CLAIMED and UNCERTAIN must never be automatically replayed.
CREATE TABLE incident_department_head_email_receipt (
    incident_id BIGINT NOT NULL,
    recipient_user_id BIGINT NOT NULL,
    status VARCHAR(10) NOT NULL,
    claimed_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    finished_at DATETIME(6) NULL,
    PRIMARY KEY (incident_id, recipient_user_id),
    CONSTRAINT fk_head_email_incident FOREIGN KEY (incident_id) REFERENCES incidents(id),
    CONSTRAINT fk_head_email_recipient FOREIGN KEY (recipient_user_id) REFERENCES app_users(id),
    CONSTRAINT ck_head_email_status CHECK (status IN ('CLAIMED','SENT','UNCERTAIN'))
) ENGINE=InnoDB;
