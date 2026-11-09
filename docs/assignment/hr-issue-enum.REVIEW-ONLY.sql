-- REVIEW ONLY. Applies solely to the verified five-member baseline native ENUM below.
-- DBA preflight: compare SHOW CREATE TABLE incidents and the column metadata.
-- Preserve column attributes, member order, nullability, character set, collation
-- and default. If any differ, stop and review a definition derived from that schema.
-- Do not run for an unconstrained VARCHAR or an already extended ENUM.
SELECT COLUMN_TYPE, IS_NULLABLE, COLUMN_DEFAULT, CHARACTER_SET_NAME, COLLATION_NAME
FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'incidents' AND COLUMN_NAME = 'issue_type';

ALTER TABLE incidents MODIFY COLUMN issue_type ENUM(
    'INFORMATION_SECURITY_INCIDENT', 'IT_ISSUE', 'MAJOR_CRITICAL_SECURITY_INCIDENT',
    'SERVICE_REQUEST', 'SUSPECTED_SECURITY_INCIDENT', 'HR_ISSUE'
) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL;

-- Retain HR_ISSUE on rollback. A prior binary cannot safely read stored HR_ISSUE rows.
