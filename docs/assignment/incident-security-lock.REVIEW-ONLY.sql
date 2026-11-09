-- REVIEW ONLY for existing databases. Preflight and separately approve.
-- Apply after incident-security-administration.REVIEW-ONLY.sql and before activation.
CREATE TABLE incident_security_lock (
    id BIGINT NOT NULL PRIMARY KEY,
    CONSTRAINT ck_incident_security_lock_singleton CHECK (id=1)
) ENGINE=InnoDB;
INSERT INTO incident_security_lock(id) VALUES (1);
-- Application principal: SELECT and column-level UPDATE(id), no INSERT/DELETE.
-- MySQL FOR UPDATE requires SELECT plus UPDATE/DELETE/LOCK TABLES. UPDATE(id)
-- satisfies it; CHECK(id=1) prevents changing the singleton identity. Verify grants.
-- Rollback: disable functionality and retain the gate/security/audit tables.

-- Verify this index name is absent before the independently approved migration.
CREATE INDEX idx_incidents_security_created ON incidents(created_at,id);
