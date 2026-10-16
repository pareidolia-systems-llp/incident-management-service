-- Explicit additive DDL for development or a separately approved production release.
-- Not run by Spring at startup (this is not schema.sql and is outside resources).
-- Prerequisites: select the correct schema; app_users.id must be signed BIGINT,
-- app_users must use InnoDB, and work_log_entries must not already exist.
-- If already present, inspect it rather than hiding drift with IF NOT EXISTS.
CREATE TABLE work_log_entries (
    id BIGINT NOT NULL AUTO_INCREMENT,
    owner_id BIGINT NOT NULL,
    worked_at DATETIME(6) NOT NULL,
    category VARCHAR(32) NOT NULL,
    summary VARCHAR(255) NOT NULL,
    details TEXT NULL,
    duration_minutes INT NULL,
    created_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    INDEX idx_work_log_owner_worked_id (owner_id, worked_at, id),
    CONSTRAINT fk_work_log_owner FOREIGN KEY (owner_id)
        REFERENCES app_users (id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
