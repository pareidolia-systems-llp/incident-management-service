-- REVIEW ONLY. Requires existing incidents, app_users and employee_departments.
-- Do not provision approvals until ISMS/HR approves independent issuers and review scope.
-- Transfer verification needs SELECT. The approved portal issuer and reviewer writes take
-- incident_security_lock exclusively and append a decision audit in the same transaction.
-- Successful transfer advances assignment_version, preventing reuse at a later version.
CREATE TABLE incident_transfer_handoff_approvals (
    approval_reference VARCHAR(100) NOT NULL PRIMARY KEY,
    incident_id BIGINT NOT NULL,
    coordinator_user_id BIGINT NOT NULL,
    source_department_id BIGINT NOT NULL,
    destination_department_id BIGINT NOT NULL,
    destination_handler_user_id BIGINT NOT NULL,
    assignment_version BIGINT NOT NULL,
    classification_version BIGINT NOT NULL,
    approved_by_user_id BIGINT NULL,
    approved_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at DATETIME(6) NULL,
    decision_status VARCHAR(12) NOT NULL DEFAULT 'PENDING',
    decision_version BIGINT NOT NULL DEFAULT 0,
    requested_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    request_reason VARCHAR(500) NOT NULL DEFAULT '',
    revoked_at DATETIME(6) NULL,
    CONSTRAINT fk_handoff_incident FOREIGN KEY (incident_id) REFERENCES incidents(id),
    CONSTRAINT fk_handoff_coordinator FOREIGN KEY (coordinator_user_id) REFERENCES app_users(id),
    CONSTRAINT fk_handoff_source FOREIGN KEY (source_department_id) REFERENCES employee_departments(id),
    CONSTRAINT fk_handoff_destination FOREIGN KEY (destination_department_id) REFERENCES employee_departments(id),
    CONSTRAINT fk_handoff_handler FOREIGN KEY (destination_handler_user_id) REFERENCES app_users(id),
    CONSTRAINT fk_handoff_approver FOREIGN KEY (approved_by_user_id) REFERENCES app_users(id),
    CONSTRAINT ck_handoff_independent CHECK (approved_by_user_id <> coordinator_user_id
                                           AND approved_by_user_id <> destination_handler_user_id),
    CONSTRAINT ck_handoff_departments CHECK (source_department_id <> destination_department_id),
    CONSTRAINT ck_handoff_versions CHECK (assignment_version >= 0 AND classification_version > 0),
    CONSTRAINT ck_handoff_expiry CHECK (expires_at > approved_at),
    CONSTRAINT ck_handoff_status CHECK (decision_status IN ('PENDING','APPROVED','REJECTED','REVOKED')),
    CONSTRAINT ck_handoff_approved CHECK (decision_status <> 'APPROVED' OR
                                         (approved_by_user_id IS NOT NULL AND expires_at IS NOT NULL))
) ENGINE=InnoDB;

CREATE TABLE incident_transfer_handoff_audit (
    approval_reference VARCHAR(100) NOT NULL,
    decision_version BIGINT NOT NULL,
    actor_user_id BIGINT NOT NULL,
    decision_status VARCHAR(12) NOT NULL,
    reason VARCHAR(500) NOT NULL,
    changed_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (approval_reference, decision_version),
    CONSTRAINT fk_handoff_audit_reference FOREIGN KEY (approval_reference)
        REFERENCES incident_transfer_handoff_approvals(approval_reference),
    CONSTRAINT fk_handoff_audit_actor FOREIGN KEY (actor_user_id) REFERENCES app_users(id),
    CONSTRAINT ck_handoff_audit_reason CHECK (char_length(trim(reason)) > 0)
) ENGINE=InnoDB;
