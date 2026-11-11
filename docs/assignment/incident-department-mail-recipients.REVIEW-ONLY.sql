-- REVIEW ONLY. Back up and verify employee_departments, app_users, and
-- incident_department_head_email_receipt before applying. Apply DDL once.
-- Existing department IDs, inactive states, and incident references are retained.
-- Abort activation if any approved department already exists but is inactive.
CREATE TABLE incident_department_mail_recipient (
    id CHAR(36) NOT NULL PRIMARY KEY,
    department_id BIGINT NOT NULL,
    email VARCHAR(254) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    version BIGINT NOT NULL DEFAULT 0,
    UNIQUE KEY uk_department_mail_address (department_id, email),
    CONSTRAINT fk_department_mail_department FOREIGN KEY (department_id) REFERENCES employee_departments(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE incident_department_mail_recipient_audit (
    recipient_id CHAR(36) NOT NULL,
    actor_user_id BIGINT NOT NULL,
    old_email VARCHAR(254) NULL,
    new_email VARCHAR(254) NOT NULL,
    old_active BOOLEAN NULL,
    new_active BOOLEAN NOT NULL,
    version BIGINT NOT NULL,
    reason VARCHAR(500) NOT NULL,
    changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (recipient_id, version),
    CONSTRAINT fk_department_mail_audit_recipient FOREIGN KEY (recipient_id) REFERENCES incident_department_mail_recipient(id),
    CONSTRAINT fk_department_mail_audit_actor FOREIGN KEY (actor_user_id) REFERENCES app_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- Run this initial data transaction once after verifying canonical department names
-- and recipient identity mappings. Deploy with all delivery flags off.
START TRANSACTION;
INSERT INTO employee_departments (display_name)
VALUES ('IT'), ('Operations (Annotation)'), ('Operations (Perioperative Flow Analysis)'), ('R&D')
ON DUPLICATE KEY UPDATE display_name=employee_departments.display_name;

INSERT INTO employee_departments (display_name)
SELECT 'HR' WHERE NOT EXISTS (
    SELECT 1 FROM employee_departments WHERE display_name IN ('HR', 'Human Resources')
);

INSERT INTO incident_department_mail_recipient (id, department_id, email)
SELECT UUID(), d.id, seed.email
FROM employee_departments d
JOIN (
    SELECT 'IT' AS department, 'itadmin@pareidolia.in' AS email
    UNION ALL SELECT 'HR', 'schakravorty@pareidolia.in'
    UNION ALL SELECT 'Operations (Annotation)', 'annotator@pareidolia.in'
    UNION ALL SELECT 'Operations (Annotation)', 'annotator02@pareidolia.in'
    UNION ALL SELECT 'Operations (Perioperative Flow Analysis)', 'annotator@pareidolia.in'
    UNION ALL SELECT 'Operations (Perioperative Flow Analysis)', 'annotator02@pareidolia.in'
    UNION ALL SELECT 'R&D', 'debolina@pareidolia.in'
) seed ON seed.department=d.display_name OR (seed.department='HR' AND d.display_name='Human Resources')
WHERE d.active=TRUE;
COMMIT;
