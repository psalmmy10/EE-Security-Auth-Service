-- Absolute lifetime of a login (token family). Refresh rotation can no longer extend a session forever.
ALTER TABLE user_sessions ADD COLUMN family_expires_at TIMESTAMPTZ;
UPDATE user_sessions SET family_expires_at = expires_at WHERE family_expires_at IS NULL;
ALTER TABLE user_sessions ALTER COLUMN family_expires_at SET NOT NULL;

-- Supports the active-session limit lookup (oldest first per user)
CREATE INDEX idx_user_sessions_user_created ON user_sessions (user_id, created_at) WHERE revoked_at IS NULL;
