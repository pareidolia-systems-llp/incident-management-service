-- REVIEW ONLY. Requires B3 employee_departments and the existing app_users.
-- No seed grants or inferred memberships. Writers must hold the B4 security gate.
CREATE TABLE employee_department_memberships (
    department_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    active TINYINT NOT NULL DEFAULT 0,
    PRIMARY KEY (department_id, user_id),
    CONSTRAINT ck_department_membership_active CHECK (active IN (0, 1)),
    CONSTRAINT fk_membership_department FOREIGN KEY (department_id)
        REFERENCES employee_departments(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_membership_user FOREIGN KEY (user_id)
        REFERENCES app_users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
);
