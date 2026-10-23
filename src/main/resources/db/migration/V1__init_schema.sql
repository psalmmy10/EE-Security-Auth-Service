-- =====================================================================
-- Identity & access schema
--   users  >--<  roles  >--<  permissions     (many-to-many via join tables)
--   users  --<   user_sessions                (one-to-many, cascade on delete)
--   audit_logs                                (append-only, deliberately NO FK so
--                                              audit history survives user deletion)
-- =====================================================================

CREATE TABLE users (
    id                     UUID         PRIMARY KEY,
    email                  VARCHAR(150) NOT NULL,
    password_hash          VARCHAR(255) NOT NULL,
    first_name             VARCHAR(100) NOT NULL,
    last_name              VARCHAR(100) NOT NULL,
    status                 VARCHAR(20)  NOT NULL,
    failed_login_attempts  INT          NOT NULL DEFAULT 0,
    locked_until           TIMESTAMPTZ,
    last_login_at          TIMESTAMPTZ,
    created_at             TIMESTAMPTZ  NOT NULL,
    updated_at             TIMESTAMPTZ  NOT NULL,
    version                BIGINT       NOT NULL DEFAULT 0,
    CONSTRAINT uk_users_email UNIQUE (email),
    CONSTRAINT ck_users_status CHECK (status IN ('ACTIVE', 'LOCKED', 'DISABLED')),
    CONSTRAINT ck_users_failed_attempts CHECK (failed_login_attempts >= 0)
);

CREATE TABLE roles (
    id           UUID         PRIMARY KEY,
    name         VARCHAR(30)  NOT NULL,
    description  VARCHAR(150),
    created_at   TIMESTAMPTZ  NOT NULL,
    updated_at   TIMESTAMPTZ  NOT NULL,
    version      BIGINT       NOT NULL DEFAULT 0,
    CONSTRAINT uk_roles_name UNIQUE (name)
);

CREATE TABLE permissions (
    id           UUID         PRIMARY KEY,
    name         VARCHAR(50)  NOT NULL,
    description  VARCHAR(150),
    created_at   TIMESTAMPTZ  NOT NULL,
    updated_at   TIMESTAMPTZ  NOT NULL,
    version      BIGINT       NOT NULL DEFAULT 0,
    CONSTRAINT uk_permissions_name UNIQUE (name)
);

CREATE TABLE user_roles (
    user_id  UUID NOT NULL,
    role_id  UUID NOT NULL,
    CONSTRAINT pk_user_roles PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE RESTRICT
);
CREATE INDEX idx_user_roles_role ON user_roles (role_id);

CREATE TABLE role_permissions (
    role_id        UUID NOT NULL,
    permission_id  UUID NOT NULL,
    CONSTRAINT pk_role_permissions PRIMARY KEY (role_id, permission_id),
    CONSTRAINT fk_role_permissions_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE,
    CONSTRAINT fk_role_permissions_permission FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE RESTRICT
);
CREATE INDEX idx_role_permissions_permission ON role_permissions (permission_id);

CREATE TABLE user_sessions (
    id                  UUID         PRIMARY KEY,
    user_id             UUID         NOT NULL,
    family_id           UUID         NOT NULL,
    access_token_jti    VARCHAR(64)  NOT NULL,
    refresh_token_hash  VARCHAR(64)  NOT NULL,
    ip_address          VARCHAR(45),
    user_agent          VARCHAR(255),
    access_expires_at   TIMESTAMPTZ  NOT NULL,
    expires_at          TIMESTAMPTZ  NOT NULL,
    revoked_at          TIMESTAMPTZ,
    revocation_reason   VARCHAR(30),
    created_at          TIMESTAMPTZ  NOT NULL,
    updated_at          TIMESTAMPTZ  NOT NULL,
    version             BIGINT       NOT NULL DEFAULT 0,
    CONSTRAINT fk_user_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT uk_user_sessions_jti UNIQUE (access_token_jti),
    CONSTRAINT uk_user_sessions_refresh UNIQUE (refresh_token_hash)
);
CREATE INDEX idx_user_sessions_user_active ON user_sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_user_sessions_family ON user_sessions (family_id);
CREATE INDEX idx_user_sessions_expires ON user_sessions (expires_at);

CREATE TABLE audit_logs (
    id           UUID         PRIMARY KEY,
    event_type   VARCHAR(40)  NOT NULL,
    user_id      UUID,
    principal    VARCHAR(150),
    ip_address   VARCHAR(45),
    user_agent   VARCHAR(255),
    detail       VARCHAR(500),
    occurred_at  TIMESTAMPTZ  NOT NULL,
    created_at   TIMESTAMPTZ  NOT NULL,
    updated_at   TIMESTAMPTZ  NOT NULL,
    version      BIGINT       NOT NULL DEFAULT 0
);
CREATE INDEX idx_audit_logs_user_time ON audit_logs (user_id, occurred_at DESC);
CREATE INDEX idx_audit_logs_type_time ON audit_logs (event_type, occurred_at DESC);
