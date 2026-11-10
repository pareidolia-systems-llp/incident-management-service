-- REVIEW ONLY. Additive, no backfill. Requires app_users and incidents.
-- Restrict this evidence to authorized HR/security operators. Give the referral runtime
-- SELECT and INSERT only on these tables. Reserve UPDATE/DELETE and DDL for audited DBA controls.
-- The submitted reference is deliberately not a foreign key and never resolves during intake.
CREATE TABLE hr_reassignment_referral_intake (
    id CHAR(36) NOT NULL PRIMARY KEY,
    requester_id BIGINT NOT NULL,
    incident_reference VARCHAR(40) NULL,
    received_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_hr_referral_requester_time (requester_id, received_at),
    KEY idx_hr_referral_reference_time (incident_reference, received_at),
    CONSTRAINT fk_hr_referral_requester FOREIGN KEY (requester_id) REFERENCES app_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE hr_reassignment_referral_decision (
    referral_id CHAR(36) NOT NULL PRIMARY KEY,
    reviewer_id BIGINT NOT NULL,
    incident_id BIGINT NOT NULL,
    outcome VARCHAR(16) NOT NULL,
    assignment_version BIGINT NOT NULL,
    reason VARCHAR(500) NOT NULL,
    decided_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_hr_referral_decision FOREIGN KEY (referral_id) REFERENCES hr_reassignment_referral_intake(id),
    CONSTRAINT fk_hr_referral_reviewer FOREIGN KEY (reviewer_id) REFERENCES app_users(id),
    CONSTRAINT fk_hr_referral_incident FOREIGN KEY (incident_id) REFERENCES incidents(id),
    CONSTRAINT ck_hr_referral_outcome CHECK (outcome IN ('REJECTED','REASSIGNED','TRANSFERRED')),
    CONSTRAINT ck_hr_referral_version CHECK (assignment_version >= 0),
    CONSTRAINT ck_hr_referral_reason CHECK (CHAR_LENGTH(TRIM(reason)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
