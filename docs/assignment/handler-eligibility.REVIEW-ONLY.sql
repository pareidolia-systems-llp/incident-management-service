-- REVIEW ONLY. No schema changes have been applied.
-- Existing app_users is the sole employee directory. Absence or inactive grant denies.
-- A grant does not authorize an actor, confer incident access, or classify a case.
CREATE TABLE handler_eligibility_grants (
    user_id BIGINT NOT NULL,
    active TINYINT NOT NULL DEFAULT 0,
    version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id),
    CONSTRAINT ck_handler_eligibility_active CHECK (active IN (0,1)),
    CONSTRAINT ck_handler_eligibility_version CHECK (version >= 0),
    CONSTRAINT fk_handler_eligibility_user FOREIGN KEY (user_id) REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB;
CREATE TABLE handler_eligibility_audit (
    id BIGINT NOT NULL AUTO_INCREMENT,
    actor_user_id BIGINT NOT NULL,
    target_user_id BIGINT NOT NULL,
    old_active TINYINT NULL,
    new_active TINYINT NOT NULL,
    grant_version BIGINT NOT NULL,
    reason VARCHAR(500) NOT NULL,
    changed_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uk_handler_eligibility_audit_version (target_user_id, grant_version),
    CONSTRAINT ck_handler_eligibility_audit_old CHECK (old_active IS NULL OR old_active IN (0,1)),
    CONSTRAINT ck_handler_eligibility_audit_new CHECK (new_active IN (0,1)),
    CONSTRAINT ck_handler_eligibility_audit_reason CHECK (CHAR_LENGTH(TRIM(reason)) > 0),
    CONSTRAINT fk_handler_eligibility_audit_actor FOREIGN KEY (actor_user_id) REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_handler_eligibility_audit_target FOREIGN KEY (target_user_id) REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB;
-- Rollback: disable future writers and retain audit and grant data. Removal of data
-- or schema requires a separate reviewed archival and migration procedure.
