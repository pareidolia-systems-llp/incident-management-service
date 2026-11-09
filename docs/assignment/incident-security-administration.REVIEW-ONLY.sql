-- REVIEW ONLY. DO NOT EXECUTE without separate DBA/ISMS approval and backup.
-- Standalone proposal supersedes classification-case-access.REVIEW-ONLY.sql and
-- incident-access.REVIEW-ONLY.sql. Do not apply both versions. Requires verified
-- existing InnoDB app_users(id) and incidents(id), with compatible BIGINT types.
-- No automatic data backfill, capability grant or seeding is included.
CREATE TABLE incident_security_classification (
  incident_id BIGINT NOT NULL PRIMARY KEY,
  classification VARCHAR(20) NOT NULL DEFAULT 'UNCLASSIFIED',
  version BIGINT NOT NULL DEFAULT 0,
  CONSTRAINT ck_isc_value CHECK (classification IN ('UNCLASSIFIED','STANDARD','RESTRICTED')),
  CONSTRAINT ck_isc_version CHECK (version >= 0),
  CONSTRAINT fk_isc_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB;
CREATE TABLE incident_classification_audit (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY, incident_id BIGINT NOT NULL, actor_user_id BIGINT NOT NULL,
  previous_classification VARCHAR(20) NOT NULL, new_classification VARCHAR(20) NOT NULL,
  version BIGINT NOT NULL, reason VARCHAR(500) NOT NULL, changed_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_ica_version (incident_id,version),
  CONSTRAINT ck_ica_reason CHECK (CHAR_LENGTH(TRIM(reason)) > 0),
  CONSTRAINT ck_ica_previous CHECK (previous_classification IN ('UNCLASSIFIED','STANDARD','RESTRICTED')),
  CONSTRAINT ck_ica_new CHECK (new_classification IN ('STANDARD','RESTRICTED')),
  CONSTRAINT ck_ica_version CHECK (version > 0),
  CONSTRAINT fk_ica_classification FOREIGN KEY (incident_id) REFERENCES incident_security_classification(incident_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_ica_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_ica_actor FOREIGN KEY (actor_user_id) REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB;
CREATE TABLE assignment_admin_capabilities (
  user_id BIGINT NOT NULL, capability VARCHAR(40) NOT NULL, active TINYINT NOT NULL DEFAULT 0, version BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id,capability),
  CONSTRAINT ck_aac_capability CHECK (capability IN ('INCIDENT_CLASSIFIER','RESTRICTED_DOWNGRADE','ASSIGNMENT_ADMIN','CASE_ACCESS_ADMIN','GLOBAL_INCIDENT_VIEW')),
  CONSTRAINT ck_aac_active CHECK (active IN (0,1)), CONSTRAINT ck_aac_version CHECK (version>=0),
  CONSTRAINT fk_aac_user FOREIGN KEY (user_id) REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB;
CREATE TABLE assignment_admin_capability_audit (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY, actor_user_id BIGINT NOT NULL, target_user_id BIGINT NOT NULL,
  capability VARCHAR(40) NOT NULL, old_active TINYINT NULL, new_active TINYINT NOT NULL, version BIGINT NOT NULL,
  reason VARCHAR(500) NOT NULL, changed_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_aaca_version (target_user_id,capability,version),
  CONSTRAINT ck_aaca_reason CHECK (CHAR_LENGTH(TRIM(reason))>0),
  CONSTRAINT ck_aaca_old CHECK (old_active IS NULL OR old_active IN (0,1)),
  CONSTRAINT ck_aaca_new CHECK (new_active IN (0,1)),
  CONSTRAINT ck_aaca_version CHECK (version > 0),
  CONSTRAINT fk_aaca_capability FOREIGN KEY (target_user_id,capability) REFERENCES assignment_admin_capabilities(user_id,capability) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_aaca_actor FOREIGN KEY (actor_user_id) REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_aaca_target FOREIGN KEY (target_user_id) REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB;
CREATE TABLE incident_security_grants (
  incident_id BIGINT NOT NULL,user_id BIGINT NOT NULL,permission VARCHAR(20) NOT NULL,active TINYINT NOT NULL DEFAULT 0,version BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (incident_id,user_id,permission),
  CONSTRAINT ck_isg_permission CHECK (permission IN ('VIEW','HANDLE','MODIFY','REPORT','ASSIGN')),
  CONSTRAINT ck_isg_active CHECK (active IN (0,1)), CONSTRAINT ck_isg_version CHECK (version>=0),
  CONSTRAINT fk_isg_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_isg_user FOREIGN KEY (user_id) REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB;
CREATE TABLE incident_security_grant_audit (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY, incident_id BIGINT NOT NULL, target_user_id BIGINT NOT NULL,
  permission VARCHAR(20) NOT NULL, actor_user_id BIGINT NOT NULL, old_active TINYINT NULL, new_active TINYINT NOT NULL,
  version BIGINT NOT NULL, reason VARCHAR(500) NOT NULL, changed_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_isga_version (incident_id,target_user_id,permission,version),
  CONSTRAINT ck_isga_reason CHECK (CHAR_LENGTH(TRIM(reason))>0),
  CONSTRAINT ck_isga_old CHECK (old_active IS NULL OR old_active IN (0,1)),
  CONSTRAINT ck_isga_new CHECK (new_active IN (0,1)),
  CONSTRAINT ck_isga_version CHECK (version > 0),
  CONSTRAINT fk_isga_grant FOREIGN KEY (incident_id,target_user_id,permission) REFERENCES incident_security_grants(incident_id,user_id,permission) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_isga_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_isga_target FOREIGN KEY (target_user_id) REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_isga_actor FOREIGN KEY (actor_user_id) REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB;
-- MySQL DDL commits implicitly. Verify audit privileges deny UPDATE and DELETE to
-- the application principal; independently retain security audit and DBA actions.
-- Roll back application/configuration first while retaining rows and audit data;
-- any destructive DDL requires a separate approved archival and migration plan.

-- Structured privileged-read evidence. Grant the runtime account INSERT only
-- for this table; restrict audit review, retention and export separately.
CREATE TABLE incident_global_view_audit (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  actor_user_id BIGINT NOT NULL,
  incident_id BIGINT NOT NULL,
  operation VARCHAR(32) NOT NULL,
  accessed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_global_view_actor_time (actor_user_id, accessed_at),
  KEY idx_global_view_incident_time (incident_id, accessed_at),
  CONSTRAINT fk_global_view_actor FOREIGN KEY (actor_user_id) REFERENCES app_users(id),
  CONSTRAINT fk_global_view_incident FOREIGN KEY (incident_id) REFERENCES incidents(id)
);
