CREATE TABLE roles (
  id SERIAL PRIMARY KEY,
  name VARCHAR(50) UNIQUE NOT NULL,
  description VARCHAR(255),
  is_system BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE permissions (
  id SERIAL PRIMARY KEY,
  key VARCHAR(100) UNIQUE NOT NULL,
  description TEXT
);

CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  encrypted_full_name TEXT,
  password_hash VARCHAR(255) NOT NULL,
  role_id INTEGER NOT NULL REFERENCES roles(id),
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE scans (
  id SERIAL PRIMARY KEY,
  domain VARCHAR(255) NOT NULL,
  status VARCHAR(30) DEFAULT 'queued',
  requested_by INTEGER NOT NULL REFERENCES users(id),
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  risk_score INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE findings (
  id SERIAL PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scans(id),
  finding_type VARCHAR(100) NOT NULL,
  title VARCHAR(255) NOT NULL,
  description TEXT NOT NULL,
  severity VARCHAR(20) NOT NULL,
  stride VARCHAR(30) NOT NULL,
  remediation TEXT NOT NULL,
  evidence TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE reports (
  id SERIAL PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scans(id),
  generated_by INTEGER NOT NULL REFERENCES users(id),
  file_path TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE audit_logs (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  action VARCHAR(100) NOT NULL,
  resource VARCHAR(100) NOT NULL,
  log_metadata TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE token_blacklist (
  id SERIAL PRIMARY KEY,
  jti VARCHAR(100) UNIQUE NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);
