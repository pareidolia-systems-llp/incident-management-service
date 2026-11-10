-- REVIEW ONLY. Requires hr-reassignment-referral.REVIEW-ONLY.sql.
-- One claim per referral and recipient. A stale CLAIMED or UNCERTAIN result
-- requires transport reconciliation before any manual replay.
CREATE TABLE hr_referral_email_receipt (
    referral_id CHAR(36) NOT NULL,
    recipient_id BIGINT NOT NULL,
    status VARCHAR(10) NOT NULL,
    claimed_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    finished_at TIMESTAMP(6) NULL,
    PRIMARY KEY (referral_id, recipient_id),
    CONSTRAINT fk_hr_referral_email_intake FOREIGN KEY (referral_id) REFERENCES hr_reassignment_referral_intake(id),
    CONSTRAINT fk_hr_referral_email_recipient FOREIGN KEY (recipient_id) REFERENCES app_users(id),
    CONSTRAINT ck_hr_referral_email_status CHECK (status IN ('CLAIMED','SENT','UNCERTAIN'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
