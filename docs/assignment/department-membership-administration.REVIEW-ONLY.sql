-- REVIEW ONLY. Requires department-membership.REVIEW-ONLY.sql and the existing app_users.
-- Verify the live schema and back up before applying. Do not run the original CREATE TABLE again.
-- Existing memberships keep their active state and start at version zero. No audit history is inferred.
ALTER TABLE employee_department_memberships
    ADD COLUMN version BIGINT NOT NULL DEFAULT 0;

ALTER TABLE employee_department_memberships
    ADD CONSTRAINT ck_department_membership_version CHECK (version >= 0);

CREATE TABLE employee_department_membership_audit (
    id BIGINT NOT NULL AUTO_INCREMENT,
    department_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    actor_user_id BIGINT NOT NULL,
    old_active TINYINT NULL,
    new_active TINYINT NOT NULL,
    membership_version BIGINT NOT NULL,
    reason VARCHAR(500) NOT NULL,
    changed_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uk_membership_audit_version (department_id, user_id, membership_version),
    CONSTRAINT ck_membership_audit_old CHECK (old_active IS NULL OR old_active IN (0, 1)),
    CONSTRAINT ck_membership_audit_new CHECK (new_active IN (0, 1)),
    CONSTRAINT ck_membership_audit_version CHECK (membership_version > 0),
    CONSTRAINT ck_membership_audit_reason CHECK (CHAR_LENGTH(TRIM(reason)) > 0),
    CONSTRAINT fk_membership_audit_membership FOREIGN KEY (department_id, user_id)
        REFERENCES employee_department_memberships(department_id, user_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_membership_audit_actor FOREIGN KEY (actor_user_id)
        REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB;

-- Runtime requires SELECT and INSERT on audit; deny UPDATE and DELETE.
-- The existing singleton from incident-security-lock.REVIEW-ONLY.sql is required at runtime.
-- Disable membership administration for rollback and retain membership and audit data.
