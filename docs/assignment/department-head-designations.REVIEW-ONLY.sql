-- REVIEW ONLY. Do not apply without separate approval and backup.
-- Capability management is disabled by default; no administrator rows are seeded.
CREATE TABLE employee_departments (
    id BIGINT NOT NULL AUTO_INCREMENT,
    display_name VARCHAR(150) NOT NULL,
    active TINYINT NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    UNIQUE KEY uk_employee_departments_name (display_name),
    CONSTRAINT ck_employee_departments_active CHECK (active IN (0, 1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE employee_mapping_admins (
    user_id BIGINT NOT NULL,
    active TINYINT NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id),
    CONSTRAINT ck_employee_mapping_admins_active CHECK (active IN (0, 1)),
    CONSTRAINT fk_employee_mapping_admins_user FOREIGN KEY (user_id)
        REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- REVIEW ONLY: designation records carry no incident permissions.
-- Standalone proposal; app_users must match reviewed production schema.
-- app_users.id is BIGINT. Do not run until separately approved and preflighted.
CREATE TABLE department_head_designations (
    department_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    active TINYINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (department_id, user_id),
    KEY idx_head_designations_user (user_id, active),
    CONSTRAINT ck_head_designations_active CHECK (active IN (0, 1)),
    CONSTRAINT ck_head_designations_version CHECK (version >= 0),
    CONSTRAINT fk_head_designations_department FOREIGN KEY (department_id) REFERENCES employee_departments(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_head_designations_user FOREIGN KEY (user_id) REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE department_head_designation_audit (
    id BIGINT NOT NULL AUTO_INCREMENT,
    department_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    actor_user_id BIGINT NOT NULL,
    old_active TINYINT NULL,
    new_active TINYINT NOT NULL,
    designation_version BIGINT NOT NULL,
    reason VARCHAR(500) NOT NULL,
    changed_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    KEY idx_head_audit_designation (department_id, user_id, changed_at, id),
    KEY idx_head_audit_actor (actor_user_id, changed_at, id),
    CONSTRAINT ck_head_audit_old CHECK (old_active IS NULL OR old_active IN (0, 1)),
    CONSTRAINT ck_head_audit_new CHECK (new_active IN (0, 1)),
    CONSTRAINT ck_head_audit_reason CHECK (CHAR_LENGTH(TRIM(reason)) > 0),
    CONSTRAINT fk_head_audit_designation FOREIGN KEY (department_id, user_id)
        REFERENCES department_head_designations(department_id, user_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_head_audit_actor FOREIGN KEY (actor_user_id) REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- Independent capability administrators; bootstrap only by separately approved procedure.
CREATE TABLE employee_capability_administrators (
    user_id BIGINT NOT NULL,
    active TINYINT NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id),
    CONSTRAINT ck_employee_capability_admin_active CHECK (active IN (0,1)),
    CONSTRAINT fk_employee_capability_admin_user FOREIGN KEY (user_id) REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- Application exposes insertion only. Database privileges and external audit retention
-- must enforce append-only behavior against direct SQL and privileged operators.
CREATE TABLE employee_mapping_admin_audit (
    id BIGINT NOT NULL AUTO_INCREMENT,
    actor_user_id BIGINT NOT NULL,
    target_user_id BIGINT NOT NULL,
    old_active TINYINT NULL,
    new_active TINYINT NOT NULL,
    reason VARCHAR(500) NOT NULL,
    changed_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    KEY idx_mapping_admin_audit_target (target_user_id,changed_at,id),
    CONSTRAINT ck_mapping_admin_audit_old CHECK (old_active IS NULL OR old_active IN (0,1)),
    CONSTRAINT ck_mapping_admin_audit_new CHECK (new_active IN (0,1)),
    CONSTRAINT ck_mapping_admin_audit_reason CHECK (CHAR_LENGTH(TRIM(reason)) > 0),
    CONSTRAINT fk_mapping_admin_audit_actor FOREIGN KEY (actor_user_id) REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_mapping_admin_audit_target FOREIGN KEY (target_user_id) REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
