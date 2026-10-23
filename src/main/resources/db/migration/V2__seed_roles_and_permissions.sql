INSERT INTO roles (id, name, description, created_at, updated_at, version) VALUES
    (gen_random_uuid(), 'USER',  'Standard customer account', now(), now(), 0),
    (gen_random_uuid(), 'ADMIN', 'Platform administrator',    now(), now(), 0);

INSERT INTO permissions (id, name, description, created_at, updated_at, version) VALUES
    (gen_random_uuid(), 'PROFILE_READ',   'Read own profile',          now(), now(), 0),
    (gen_random_uuid(), 'PROFILE_UPDATE', 'Update own profile',        now(), now(), 0),
    (gen_random_uuid(), 'USER_READ',      'Read any user account',     now(), now(), 0),
    (gen_random_uuid(), 'USER_MANAGE',    'Change user account state', now(), now(), 0),
    (gen_random_uuid(), 'ROLE_MANAGE',    'Assign and revoke roles',   now(), now(), 0),
    (gen_random_uuid(), 'AUDIT_READ',     'Read audit trail',          now(), now(), 0);

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.name IN ('PROFILE_READ', 'PROFILE_UPDATE')
WHERE r.name = 'USER';

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'ADMIN';
