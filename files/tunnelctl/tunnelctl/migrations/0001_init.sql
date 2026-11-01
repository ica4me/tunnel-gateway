CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO schema_meta VALUES ('schema_version','1');
CREATE TABLE accounts (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL,
 protocol TEXT NOT NULL CHECK(protocol IN ('ssh','vmess','vless','trojan','ss')),
 secret TEXT NOT NULL, is_trial INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
 quota_bytes INTEGER NOT NULL DEFAULT 0 CHECK(quota_bytes>=0),
 used_up INTEGER NOT NULL DEFAULT 0 CHECK(used_up>=0),
 used_down INTEGER NOT NULL DEFAULT 0 CHECK(used_down>=0),
 ip_limit INTEGER NOT NULL DEFAULT 0 CHECK(ip_limit>=0),
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','locked','expired','quota_exceeded','limit_locked')),
 lock_reason TEXT, lock_until TEXT, violation_count INTEGER NOT NULL DEFAULT 0,
 note TEXT, updated_at TEXT NOT NULL, UNIQUE(username,protocol));
CREATE TABLE usage_daily (account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 day TEXT NOT NULL, up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(account_id,day));
CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT,ts TEXT NOT NULL,account_id INTEGER,
 actor TEXT NOT NULL,action TEXT NOT NULL,detail TEXT);
CREATE TABLE settings (key TEXT PRIMARY KEY,value TEXT NOT NULL);
