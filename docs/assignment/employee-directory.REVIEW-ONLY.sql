-- REVIEW ONLY: do not run without independent schema review, backup and approval.
-- Existing app_users remains the employee directory. Preflight existing columns,
-- normalized email uniqueness, employee IDs, engine, ID types and MySQL collation.
ALTER TABLE app_users
  ADD COLUMN employee_id VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin NULL,
  ADD COLUMN account_version BIGINT NOT NULL DEFAULT 0,
  ADD CONSTRAINT uk_app_users_employee_id UNIQUE (employee_id);
CREATE TABLE employee_management_audit (
  id BIGINT NOT NULL AUTO_INCREMENT,
  actor_id BIGINT NOT NULL,
  target_id BIGINT NOT NULL,
  action VARCHAR(20) NOT NULL,
  old_employee_id VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin NULL,
  new_employee_id VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin NULL,
  old_name VARCHAR(255) NULL,
  new_name VARCHAR(255) NOT NULL,
  old_active TINYINT NULL,
  new_active TINYINT NOT NULL,
  version BIGINT NOT NULL,
  reason VARCHAR(500) NOT NULL,
  changed_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  UNIQUE KEY uk_employee_management_target_version (target_id,version),
  CONSTRAINT fk_employee_management_actor FOREIGN KEY (actor_id) REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_employee_management_target FOREIGN KEY (target_id) REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT ck_employee_management_action CHECK (action IN ('CREATE','UPDATE','STATUS')),
  CONSTRAINT ck_employee_management_reason CHECK (CHAR_LENGTH(TRIM(reason)) > 0)
) ENGINE=InnoDB;
-- Rollback: disable the feature and retain employee IDs and audit history.
-- Do not drop populated columns or tables without separately approved retention
-- and reconciliation. MySQL DDL commits implicitly; rehearse in disposable 8.4.
