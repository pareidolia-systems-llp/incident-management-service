-- REVIEW ONLY. Requires reviewed responsible-department and assignment schemas.
-- No backfill, authorization grant, or data modification. Restrict audit read access separately.
CREATE TABLE incident_department_transfer_audit (
    id BIGINT NOT NULL AUTO_INCREMENT,
    incident_id BIGINT NOT NULL,
    actor_user_id BIGINT NOT NULL,
    source_department_id BIGINT NOT NULL,
    destination_department_id BIGINT NOT NULL,
    previous_handler_user_id BIGINT NULL,
    new_handler_user_id BIGINT NOT NULL,
    assignment_version BIGINT NOT NULL,
    classification_version BIGINT NOT NULL,
    reason VARCHAR(500) NOT NULL,
    handoff_approval_reference VARCHAR(100) NOT NULL,
    changed_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uk_transfer_audit_version (incident_id, assignment_version),
    CONSTRAINT ck_transfer_departments CHECK (source_department_id <> destination_department_id),
    CONSTRAINT ck_transfer_assignment_version CHECK (assignment_version > 0),
    CONSTRAINT ck_transfer_classification_version CHECK (classification_version > 0),
    CONSTRAINT ck_transfer_reason CHECK (CHAR_LENGTH(TRIM(reason)) > 0),
    CONSTRAINT ck_transfer_approval CHECK (CHAR_LENGTH(TRIM(handoff_approval_reference)) > 0),
    CONSTRAINT fk_transfer_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_transfer_actor FOREIGN KEY (actor_user_id) REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_transfer_source FOREIGN KEY (source_department_id) REFERENCES employee_departments(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_transfer_destination FOREIGN KEY (destination_department_id) REFERENCES employee_departments(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_transfer_previous_handler FOREIGN KEY (previous_handler_user_id) REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_transfer_new_handler FOREIGN KEY (new_handler_user_id) REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB;

-- Transfer runtime needs INSERT only on this table. Deny UPDATE and DELETE.
-- Disable transfer for rollback and retain audit rows.
