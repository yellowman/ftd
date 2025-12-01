CREATE TABLE IF NOT EXISTS submissions (
    id SERIAL PRIMARY KEY,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address TEXT,
    user_agent TEXT,
    referer TEXT,
    status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','in_progress','complete','archived')),
    file_path TEXT,
    comment TEXT,
    form_data JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS submissions_status_submitted_at_idx
    ON submissions (status, submitted_at DESC);

CREATE INDEX IF NOT EXISTS submissions_submitted_at_idx
    ON submissions (submitted_at DESC);

CREATE TABLE IF NOT EXISTS admin_users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Default admin user; change this password immediately via the dashboard.
INSERT INTO admin_users (username, password_hash)
VALUES ('admin', '$2b$12$R3PN9SNYhLYD3ruOZ3qMJ.gnIK8POtoTLbHKni/mc1C.Y9hDpoteu')
ON CONFLICT (username) DO NOTHING;

CREATE TABLE IF NOT EXISTS submission_blocks (
    scope TEXT NOT NULL CHECK (scope IN ('ip','global')),
    identifier TEXT NOT NULL,
    blocked_until TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (scope, identifier)
);

CREATE INDEX IF NOT EXISTS submission_blocks_until_idx ON submission_blocks (blocked_until);
