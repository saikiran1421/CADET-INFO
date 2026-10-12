PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS units(id INTEGER PRIMARY KEY, unit_name TEXT NOT NULL UNIQUE, battalion TEXT NOT NULL, institution TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now')));
-- users holds all roles. ANOs/cadets belong to one unit (ano_users from the spec is folded into users: ano_id + unit_id).
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN('CADET','ANO','SUPER_ADMIN')), cadet_id TEXT UNIQUE COLLATE NOCASE, ano_id TEXT UNIQUE COLLATE NOCASE,
 unit_id INTEGER REFERENCES units(id), active INTEGER NOT NULL DEFAULT 1, last_login TEXT, prev_login TEXT,
 created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS cadet_profiles(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE, cadet_id TEXT,
 student_id TEXT DEFAULT '', full_name TEXT DEFAULT '', dob TEXT DEFAULT '', gender TEXT DEFAULT '', college TEXT DEFAULT '', department TEXT DEFAULT '', year TEXT DEFAULT '',
 phone TEXT DEFAULT '', email TEXT DEFAULT '', address TEXT DEFAULT '', ncc_unit TEXT DEFAULT '', battalion TEXT DEFAULT '', wing TEXT DEFAULT '',
 enrollment_number TEXT DEFAULT '', ncc_rank TEXT DEFAULT '', enrollment_date TEXT DEFAULT '', current_ncc_year TEXT DEFAULT '', ano_name TEXT DEFAULT '',
 created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS camps(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, camp_name TEXT NOT NULL, camp_type TEXT NOT NULL,
 location TEXT NOT NULL, from_date TEXT NOT NULL, to_date TEXT NOT NULL, number_of_days INTEGER NOT NULL, organizing_unit TEXT DEFAULT '', certificate_number TEXT DEFAULT '',
 status TEXT NOT NULL, experience TEXT DEFAULT '', created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS certificates(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, camp_id INTEGER REFERENCES camps(id) ON DELETE SET NULL,
 certificate_type TEXT NOT NULL, file_name TEXT NOT NULL, stored_name TEXT NOT NULL, file_size INTEGER NOT NULL, mime_type TEXT NOT NULL, uploaded_at TEXT DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY, at TEXT DEFAULT (datetime('now')), actor_id INTEGER, actor_label TEXT, action TEXT NOT NULL, target TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS idx_users_unit ON users(unit_id); CREATE INDEX IF NOT EXISTS idx_camps_user ON camps(user_id); CREATE INDEX IF NOT EXISTS idx_certs_user ON certificates(user_id);
