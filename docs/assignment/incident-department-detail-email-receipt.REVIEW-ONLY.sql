-- REVIEW ONLY: apply once after incident and app_users tables exist.
-- Back up and rehearse restoration before applying. Existing receipts remain intact.
-- CLAIMED and UNCERTAIN require manual reconciliation; never automatically replay.
CREATE TABLE incident_department_detail_email_receipt (
    incident_id BIGINT NOT NULL,
    recipient_user_id BIGINT NOT NULL,
    status VARCHAR(10) NOT NULL,
    claimed_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    finished_at DATETIME(6) NULL,
    PRIMARY KEY (incident_id, recipient_user_id),
    CONSTRAINT fk_detail_email_incident FOREIGN KEY (incident_id) REFERENCES incidents(id),
    CONSTRAINT fk_detail_email_recipient FOREIGN KEY (recipient_user_id) REFERENCES app_users(id),
    CONSTRAINT ck_detail_email_status CHECK (status IN ('CLAIMED','SENT','UNCERTAIN'))
) ENGINE=InnoDB;