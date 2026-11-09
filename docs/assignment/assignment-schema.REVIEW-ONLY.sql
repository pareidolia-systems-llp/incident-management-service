-- REVIEW ONLY. Do not apply to existing DEV or production databases. Disposable synthetic tests only until approved.
-- Verify production SHOW CREATE TABLE, engines, ID types, collations and index names.
-- This isolated table deliberately leaves legacy assigned_owner and history untouched.
-- A missing row means legacy/unmigrated, never an authorization or classification.
-- The schema is inert without a separately approved, fail-closed application policy.
CREATE TABLE incident_assignment_state (
    incident_id BIGINT NOT NULL,
    handler_user_id BIGINT NULL,
    proposed_handler_user_id BIGINT NULL,
    assignment_version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (incident_id),
    KEY idx_assignment_handler (handler_user_id),
    CONSTRAINT ck_assignment_version CHECK (assignment_version >= 0),
    CONSTRAINT fk_assignment_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_assignment_proposed_handler FOREIGN KEY (proposed_handler_user_id) REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_assignment_handler FOREIGN KEY (handler_user_id) REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB;

-- Stable identities alongside existing incident history; insert in the same transaction.
-- Initial assignment may have no previous handler; reassignment requires a reason.
CREATE TABLE incident_assignment_audit (
    id BIGINT NOT NULL AUTO_INCREMENT,
    incident_id BIGINT NOT NULL,
    actor_user_id BIGINT NOT NULL,
    previous_handler_user_id BIGINT NULL,
    new_handler_user_id BIGINT NOT NULL,
    assignment_version BIGINT NOT NULL,
    action_type VARCHAR(20) NOT NULL,
    reason VARCHAR(500) NOT NULL,
    changed_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uk_assignment_audit_version (incident_id, assignment_version),
    CONSTRAINT ck_assignment_action CHECK (action_type IN ('INITIAL', 'REASSIGN')),
    CONSTRAINT ck_assignment_reason CHECK (CHAR_LENGTH(TRIM(reason)) > 0),
    CONSTRAINT ck_assignment_audit_version CHECK (assignment_version > 0),
    CONSTRAINT fk_assignment_audit_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_assignment_audit_actor FOREIGN KEY (actor_user_id) REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_assignment_audit_previous FOREIGN KEY (previous_handler_user_id) REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_assignment_audit_new FOREIGN KEY (new_handler_user_id) REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB;

-- ROLLBACK GUIDANCE ONLY: Never drop populated assignment/audit data as a routine
-- rollback. Disable new writers, retain the tables and restore the prior application.
-- Data reconciliation, archival, and any eventual DDL removal need separate review.
