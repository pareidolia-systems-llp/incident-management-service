CREATE TABLE incident_security_lock (id BIGINT PRIMARY KEY);
INSERT INTO incident_security_lock (id) VALUES (1);

CREATE TABLE incident_security_classification (
    incident_id BIGINT PRIMARY KEY,
    classification VARCHAR(20) NOT NULL,
    version BIGINT NOT NULL
);

CREATE TABLE incident_security_grants (
    incident_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    permission VARCHAR(20) NOT NULL,
    active TINYINT NOT NULL,
    PRIMARY KEY (incident_id, user_id, permission)
);

CREATE TABLE assignment_admin_capabilities (
    user_id BIGINT NOT NULL,
    capability VARCHAR(40) NOT NULL,
    active TINYINT NOT NULL,
    PRIMARY KEY (user_id, capability)
);
