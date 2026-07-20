CREATE TABLE IF NOT EXISTS submissions (
    id SERIAL PRIMARY KEY,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address TEXT,
    forwarded_for TEXT,
    user_agent TEXT,
    referer TEXT,
    status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','in_progress','complete','archived')),
    file_path TEXT,
    comment TEXT,
    form_data JSONB NOT NULL
);

-- Backfill columns on databases created before they were introduced, so that
-- re-running this script is sufficient to migrate an existing install.
ALTER TABLE submissions ADD COLUMN IF NOT EXISTS forwarded_for TEXT;
ALTER TABLE submissions ADD COLUMN IF NOT EXISTS customer_id INTEGER;

CREATE INDEX IF NOT EXISTS submissions_status_submitted_at_idx
    ON submissions (status, submitted_at DESC);

CREATE INDEX IF NOT EXISTS submissions_submitted_at_idx
    ON submissions (submitted_at DESC);

-- Customers / contacts: the CRM record a submission is associated with, keyed by
-- email. Submissions link to a customer via submissions.customer_id.
CREATE TABLE IF NOT EXISTS customers (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE,
    name TEXT,
    company TEXT,
    phone TEXT,
    address TEXT,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Backfill for databases created before the columns existed (see note above).
ALTER TABLE customers ADD COLUMN IF NOT EXISTS unsubscribed_at TIMESTAMPTZ;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS bounced_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS customers_email_idx ON customers (email);
CREATE INDEX IF NOT EXISTS customers_updated_at_idx ON customers (updated_at DESC);
CREATE INDEX IF NOT EXISTS submissions_customer_id_idx ON submissions (customer_id);

-- Mailing lists / segments.
CREATE TABLE IF NOT EXISTS lists (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS list_members (
    list_id INTEGER NOT NULL REFERENCES lists (id) ON DELETE CASCADE,
    customer_id INTEGER NOT NULL REFERENCES customers (id) ON DELETE CASCADE,
    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (list_id, customer_id)
);

-- Mailings (campaigns) and their per-recipient delivery/tracking rows.
CREATE TABLE IF NOT EXISTS mailings (
    id SERIAL PRIMARY KEY,
    subject TEXT NOT NULL,
    body_html TEXT NOT NULL,
    list_id INTEGER REFERENCES lists (id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','sending','sent','failed')),
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS mailing_recipients (
    id SERIAL PRIMARY KEY,
    mailing_id INTEGER NOT NULL REFERENCES mailings (id) ON DELETE CASCADE,
    customer_id INTEGER REFERENCES customers (id) ON DELETE SET NULL,
    email TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sent','failed')),
    error TEXT,
    sent_at TIMESTAMPTZ,
    opened_at TIMESTAMPTZ,
    open_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS mailing_recipients_mailing_idx ON mailing_recipients (mailing_id);

-- One row per customer per mailing: guards against duplicate deliveries if a
-- send is raced or retried. Deduplicates first so upgrades of databases that
-- predate the constraint succeed.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'mailing_recipients_customer_uidx') THEN
        DELETE FROM mailing_recipients a USING mailing_recipients b
            WHERE a.mailing_id = b.mailing_id AND a.customer_id = b.customer_id AND a.id > b.id;
        CREATE UNIQUE INDEX mailing_recipients_customer_uidx
            ON mailing_recipients (mailing_id, customer_id);
    END IF;
END $$;

-- Click tracking: links extracted from a mailing body at send time. Redirects
-- are keyed by (recipient token, link id), so no URL travels in the query
-- string and the endpoint cannot be used as an open redirect.
CREATE TABLE IF NOT EXISTS mailing_links (
    id SERIAL PRIMARY KEY,
    mailing_id INTEGER NOT NULL REFERENCES mailings (id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    click_count INTEGER NOT NULL DEFAULT 0,
    UNIQUE (mailing_id, url)
);

ALTER TABLE mailing_recipients ADD COLUMN IF NOT EXISTS clicked_at TIMESTAMPTZ;
ALTER TABLE mailing_recipients ADD COLUMN IF NOT EXISTS click_count INTEGER NOT NULL DEFAULT 0;

-- Customer activity timeline: manual notes/calls/emails/meetings.
CREATE TABLE IF NOT EXISTS activities (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers (id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('note','call','email','meeting')),
    body TEXT NOT NULL,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS activities_customer_idx ON activities (customer_id, created_at DESC);

-- Normalized tag vocabulary. Tag names are stored lowercase; customer_tags.source
-- records how the association was made (manually, declared by a submitted form,
-- inherited from a clicked mailing link, or CSV import).
CREATE TABLE IF NOT EXISTS tags (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS customer_tags (
    customer_id INTEGER NOT NULL REFERENCES customers (id) ON DELETE CASCADE,
    tag_id INTEGER NOT NULL REFERENCES tags (id) ON DELETE CASCADE,
    source TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual','form','click','import')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (customer_id, tag_id)
);

CREATE INDEX IF NOT EXISTS customer_tags_tag_idx ON customer_tags (tag_id);

-- Tags on a mailing propagate to customers who click any of its links.
CREATE TABLE IF NOT EXISTS mailing_tags (
    mailing_id INTEGER NOT NULL REFERENCES mailings (id) ON DELETE CASCADE,
    tag_id INTEGER NOT NULL REFERENCES tags (id) ON DELETE CASCADE,
    PRIMARY KEY (mailing_id, tag_id)
);

-- Per-recipient x per-link click matrix: who clicked which link, when, how often.
-- Kept at this granularity so engagement scoring can be layered on later.
CREATE TABLE IF NOT EXISTS mailing_clicks (
    recipient_id INTEGER NOT NULL REFERENCES mailing_recipients (id) ON DELETE CASCADE,
    link_id INTEGER NOT NULL REFERENCES mailing_links (id) ON DELETE CASCADE,
    first_clicked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_clicked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    click_count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (recipient_id, link_id)
);

-- One-time migration: convert the old customers.tags comma-string column into
-- the normalized tables, then drop it. Safe to re-run (the column is gone).
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'customers' AND column_name = 'tags') THEN
        INSERT INTO tags (name)
            SELECT DISTINCT lower(trim(t.name))
            FROM customers c
            CROSS JOIN LATERAL unnest(string_to_array(c.tags, ',')) AS t(name)
            WHERE trim(t.name) <> ''
            ON CONFLICT (name) DO NOTHING;
        INSERT INTO customer_tags (customer_id, tag_id, source)
            SELECT DISTINCT c.id, tg.id, 'manual'
            FROM customers c
            CROSS JOIN LATERAL unnest(string_to_array(c.tags, ',')) AS t(name)
            JOIN tags tg ON tg.name = lower(trim(t.name))
            WHERE trim(t.name) <> ''
            ON CONFLICT DO NOTHING;
        ALTER TABLE customers DROP COLUMN tags;
    END IF;
END $$;

-- Link submissions to customers once the customers table exists. Wrapped so the
-- script stays idempotent (re-running does not error if the constraint is set).
DO $$ BEGIN
    ALTER TABLE submissions ADD CONSTRAINT submissions_customer_id_fkey
        FOREIGN KEY (customer_id) REFERENCES customers (id) ON DELETE SET NULL;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS admin_users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Default admin user; change this password immediately via the dashboard.
INSERT INTO admin_users (username, password_hash)
VALUES ('admin', '$2b$12$R3PN9SNYhLYD3ruOZ3qMJ.gnIK8POtoTLbHKni/mc1C.Y9hDpoteu')
ON CONFLICT (username) DO NOTHING;

CREATE TABLE IF NOT EXISTS admin_defaults (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT INTO admin_defaults (key, value)
VALUES ('admin_default_password_hash', '$2b$12$R3PN9SNYhLYD3ruOZ3qMJ.gnIK8POtoTLbHKni/mc1C.Y9hDpoteu')
ON CONFLICT (key) DO NOTHING;

CREATE TABLE IF NOT EXISTS submission_blocks (
    scope TEXT NOT NULL CHECK (scope IN ('ip','global')),
    identifier TEXT NOT NULL,
    blocked_until TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (scope, identifier)
);

CREATE INDEX IF NOT EXISTS submission_blocks_until_idx ON submission_blocks (blocked_until);
