-- REVIEW ONLY: apply only after separate schema review and approval.
-- Requires the existing incidents table and employee_departments from
-- department-head-designations.REVIEW-ONLY.sql. Both must use InnoDB.
-- Verify the signed BIGINT ID type and the absence of these names before applying.
-- Existing incidents retain NULL; there is no inferred department backfill.
ALTER TABLE incidents
    ADD COLUMN responsible_department_id BIGINT NULL,
    ADD INDEX idx_incidents_responsible_department (responsible_department_id),
    ADD CONSTRAINT fk_incidents_responsible_department
        FOREIGN KEY (responsible_department_id) REFERENCES employee_departments(id)
        ON DELETE RESTRICT ON UPDATE RESTRICT;
