import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { createHash } from "node:crypto";

/**
 * SQLite schema and migration runner.  The first migration is intentionally a
 * complete baseline: old tables are kept intact and new data is copied into
 * the legacy software slot where ownership is unambiguous.
 */
const migrations = [
  {
    version: 1,
    name: "software-scoped-client-platform",
    sql: `
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'owner' CHECK(role IN ('owner','operator','viewer')),
        must_change_password INTEGER NOT NULL DEFAULT 0,
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL UNIQUE,
        csrf_hash TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        ip_hash TEXT,
        revoked_at TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);

      CREATE TABLE IF NOT EXISTS license_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        public_id TEXT NOT NULL UNIQUE,
        code_encrypted BLOB NOT NULL,
        status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
        expires_at TEXT,
        max_devices INTEGER NOT NULL DEFAULT 1,
        note TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        last_used_at TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_license_status ON license_keys(status);
      CREATE TABLE IF NOT EXISTS license_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license_id INTEGER NOT NULL REFERENCES license_keys(id) ON DELETE CASCADE,
        device_id TEXT NOT NULL,
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        UNIQUE(license_id, device_id)
      );
      CREATE TABLE IF NOT EXISTS variables (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        var_key TEXT NOT NULL UNIQUE,
        value_encrypted BLOB NOT NULL,
        version INTEGER NOT NULL DEFAULT 1,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license_id INTEGER REFERENCES license_keys(id) ON DELETE SET NULL,
        device_id TEXT NOT NULL,
        payload_encrypted BLOB NOT NULL,
        payload_size INTEGER NOT NULL,
        ip_hash TEXT,
        received_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_reports_received ON reports(received_at DESC);
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS nonce_cache (
        nonce TEXT PRIMARY KEY,
        license_id INTEGER REFERENCES license_keys(id) ON DELETE CASCADE,
        expires_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        action TEXT NOT NULL,
        object_type TEXT NOT NULL,
        object_id TEXT,
        metadata TEXT NOT NULL DEFAULT '{}',
        ip_hash TEXT,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);

      CREATE TABLE IF NOT EXISTS software_slots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        slug TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
        machine_check INTEGER NOT NULL DEFAULT 1,
        ip_check INTEGER NOT NULL DEFAULT 0,
        ip_change_policy TEXT NOT NULL DEFAULT 'deny' CHECK(ip_change_policy IN ('deny','update','allow')),
        heartbeat_timeout INTEGER NOT NULL DEFAULT 300,
        session_ttl INTEGER NOT NULL DEFAULT 604800,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_software_status ON software_slots(status);

      CREATE TABLE IF NOT EXISTS software_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        software_id INTEGER NOT NULL REFERENCES software_slots(id) ON DELETE CASCADE,
        version INTEGER NOT NULL,
        encrypted_key TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
        not_before TEXT,
        not_after TEXT,
        created_at TEXT NOT NULL,
        revoked_at TEXT,
        UNIQUE(software_id, version)
      );
      CREATE INDEX IF NOT EXISTS idx_software_keys_lookup ON software_keys(software_id, status, version DESC);

      CREATE TABLE IF NOT EXISTS license_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        software_id INTEGER NOT NULL REFERENCES software_slots(id) ON DELETE CASCADE,
        code_hash BLOB NOT NULL UNIQUE,
        public_id TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
        expires_at TEXT,
        max_devices INTEGER NOT NULL DEFAULT 1,
        note TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        last_used_at TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_license_codes_scope ON license_codes(software_id, status, id DESC);

      CREATE TABLE IF NOT EXISTS license_bindings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license_id INTEGER NOT NULL UNIQUE REFERENCES license_codes(id) ON DELETE CASCADE,
        machine_hash TEXT NOT NULL,
        ip_hash TEXT,
        machine_proof_version TEXT NOT NULL DEFAULT '1',
        first_bound_at TEXT NOT NULL,
        last_verified_at TEXT NOT NULL,
        reset_at TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_license_bindings_machine ON license_bindings(machine_hash);

      CREATE TABLE IF NOT EXISTS client_sessions (
        id TEXT PRIMARY KEY,
        software_id INTEGER NOT NULL REFERENCES software_slots(id) ON DELETE CASCADE,
        license_id INTEGER NOT NULL REFERENCES license_codes(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL UNIQUE,
        machine_hash TEXT NOT NULL,
        ip_hash TEXT,
        created_at TEXT NOT NULL,
        last_heartbeat_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        revoked_at TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_client_sessions_scope ON client_sessions(software_id, license_id, revoked_at, expires_at);
      CREATE TABLE IF NOT EXISTS client_nonces (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        software_id INTEGER NOT NULL REFERENCES software_slots(id) ON DELETE CASCADE,
        session_id TEXT REFERENCES client_sessions(id) ON DELETE CASCADE,
        nonce TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(software_id, nonce)
      );
      CREATE INDEX IF NOT EXISTS idx_client_nonces_expiry ON client_nonces(expires_at);

      CREATE TABLE IF NOT EXISTS software_variables (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        software_id INTEGER NOT NULL REFERENCES software_slots(id) ON DELETE CASCADE,
        var_key TEXT NOT NULL,
        value_encrypted TEXT NOT NULL,
        version INTEGER NOT NULL DEFAULT 1,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(software_id, var_key)
      );
      CREATE INDEX IF NOT EXISTS idx_software_variables_scope ON software_variables(software_id, enabled, version);

      CREATE TABLE IF NOT EXISTS data_slots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        software_id INTEGER NOT NULL REFERENCES software_slots(id) ON DELETE CASCADE,
        slug TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        enabled INTEGER NOT NULL DEFAULT 1,
        single_limit INTEGER NOT NULL DEFAULT 131072,
        rolling_24h_limit INTEGER NOT NULL DEFAULT 0,
        permanent_limit INTEGER NOT NULL DEFAULT 0,
        max_records INTEGER NOT NULL DEFAULT 0,
        retention_days INTEGER NOT NULL DEFAULT 90,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(software_id, slug)
      );
      CREATE INDEX IF NOT EXISTS idx_data_slots_scope ON data_slots(software_id, enabled);

      CREATE TABLE IF NOT EXISTS data_usage (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        software_id INTEGER NOT NULL REFERENCES software_slots(id) ON DELETE CASCADE,
        slot_id INTEGER NOT NULL REFERENCES data_slots(id) ON DELETE CASCADE,
        license_id INTEGER REFERENCES license_codes(id) ON DELETE CASCADE,
        permanent_bytes INTEGER NOT NULL DEFAULT 0,
        rolling_bytes INTEGER NOT NULL DEFAULT 0,
        records_count INTEGER NOT NULL DEFAULT 0,
        reserved_bytes INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL,
        UNIQUE(software_id, slot_id, license_id)
      );

      CREATE TABLE IF NOT EXISTS data_uploads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        software_id INTEGER NOT NULL REFERENCES software_slots(id) ON DELETE CASCADE,
        slot_id INTEGER NOT NULL REFERENCES data_slots(id) ON DELETE CASCADE,
        license_id INTEGER REFERENCES license_codes(id) ON DELETE SET NULL,
        session_id TEXT REFERENCES client_sessions(id) ON DELETE SET NULL,
        machine_hash TEXT,
        payload_encrypted TEXT,
        storage_path TEXT,
        size INTEGER NOT NULL,
        sha256 TEXT NOT NULL,
        received_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'received' CHECK(status IN ('reserved','received','failed','deleted'))
      );
      CREATE INDEX IF NOT EXISTS idx_data_uploads_scope ON data_uploads(software_id, slot_id, received_at DESC);
      CREATE INDEX IF NOT EXISTS idx_data_uploads_license ON data_uploads(license_id, received_at DESC);

      CREATE TABLE IF NOT EXISTS software_releases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        software_id INTEGER NOT NULL REFERENCES software_slots(id) ON DELETE CASCADE,
        version TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','published','withdrawn')),
        notes TEXT NOT NULL DEFAULT '',
        created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at TEXT NOT NULL,
        published_at TEXT,
        withdrawn_at TEXT,
        UNIQUE(software_id, version)
      );
      CREATE INDEX IF NOT EXISTS idx_releases_scope ON software_releases(software_id, status, id DESC);
      CREATE TABLE IF NOT EXISTS software_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        release_id INTEGER NOT NULL REFERENCES software_releases(id) ON DELETE CASCADE,
        original_name TEXT NOT NULL,
        storage_name TEXT NOT NULL,
        relative_path TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        size INTEGER NOT NULL,
        mime TEXT NOT NULL DEFAULT 'application/octet-stream',
        status TEXT NOT NULL DEFAULT 'ready' CHECK(status IN ('ready','deleted')),
        created_at TEXT NOT NULL,
        UNIQUE(release_id, relative_path)
      );
      CREATE INDEX IF NOT EXISTS idx_files_release ON software_files(release_id, status);

      INSERT OR IGNORE INTO software_slots
        (slug,name,description,status,machine_check,ip_check,ip_change_policy,heartbeat_timeout,session_ttl,created_at,updated_at)
        VALUES ('legacy','Legacy','Migrated legacy resources','active',1,0,'deny',300,604800,datetime('now'),datetime('now'));
      INSERT OR IGNORE INTO data_slots
        (software_id,slug,name,description,enabled,single_limit,rolling_24h_limit,permanent_limit,max_records,retention_days,created_at,updated_at)
        SELECT id,'legacy','Legacy reports','Migrated legacy reports',1,131072,0,0,0,90,datetime('now'),datetime('now')
        FROM software_slots WHERE slug='legacy';

      INSERT OR IGNORE INTO license_codes
        (software_id,code_hash,public_id,status,expires_at,max_devices,note,created_at,updated_at,last_used_at)
        SELECT s.id,l.code_encrypted,l.public_id,l.status,l.expires_at,l.max_devices,l.note,l.created_at,
               COALESCE(l.created_at,datetime('now')),l.last_used_at
        FROM license_keys l CROSS JOIN software_slots s WHERE s.slug='legacy';
      INSERT OR IGNORE INTO software_variables
        (software_id,var_key,value_encrypted,version,enabled,created_at,updated_at)
        SELECT s.id,v.var_key,v.value_encrypted,v.version,v.enabled,v.created_at,v.updated_at
        FROM variables v CROSS JOIN software_slots s WHERE s.slug='legacy';
      INSERT OR IGNORE INTO data_uploads
        (software_id,slot_id,license_id,machine_hash,payload_encrypted,size,sha256,received_at,status)
        SELECT s.id,ds.id,lc.id,'legacy-migrated',r.payload_encrypted,r.payload_size,
               lower(hex(randomblob(32))),r.received_at,'received'
        FROM reports r CROSS JOIN software_slots s JOIN data_slots ds ON ds.software_id=s.id AND ds.slug='legacy'
        LEFT JOIN license_codes lc ON lc.public_id=(SELECT public_id FROM license_keys WHERE id=r.license_id)
        WHERE s.slug='legacy';
    `,
  },
  {
    version: 2,
    name: "session-revocation-and-maintenance",
    sql: "session revocation and maintenance indexes",
    apply(db) {
      const columns = db.prepare("PRAGMA table_info(sessions)").all();
      if (!columns.some((column) => column.name === "revoked_at")) db.exec("ALTER TABLE sessions ADD COLUMN revoked_at TEXT");
      db.exec("CREATE INDEX IF NOT EXISTS idx_sessions_revoked ON sessions(revoked_at)");
      db.exec("CREATE INDEX IF NOT EXISTS idx_bindings_verified ON license_bindings(last_verified_at)");
      db.exec("CREATE INDEX IF NOT EXISTS idx_uploads_status ON data_uploads(status, received_at)");
    },
  },
  {
    version: 3,
    name: "quota-and-legacy-reconciliation",
    sql: "quota indexes and legacy reconciliation",
    apply(db) {
      db.exec("CREATE INDEX IF NOT EXISTS idx_data_usage_scope ON data_usage(software_id, slot_id, license_id)");
      db.exec("CREATE INDEX IF NOT EXISTS idx_data_uploads_rolling ON data_uploads(software_id, slot_id, license_id, status, received_at)");
      db.exec("CREATE INDEX IF NOT EXISTS idx_client_sessions_token_scope ON client_sessions(software_id, token_hash)");
      db.exec("UPDATE data_usage SET rolling_bytes=COALESCE((SELECT SUM(size) FROM data_uploads u WHERE u.software_id=data_usage.software_id AND u.slot_id=data_usage.slot_id AND u.license_id=data_usage.license_id AND u.status='received' AND u.received_at>=datetime('now','-24 hours')),0), reserved_bytes=0, updated_at=datetime('now')");
    },
  },
  {
    version: 4,
    name: "one-time-key-export",
    sql: "software key export audit state",
    apply(db) {
      const columns = db.prepare("PRAGMA table_info(software_keys)").all();
      if (!columns.some((column) => column.name === "exported_at")) db.exec("ALTER TABLE software_keys ADD COLUMN exported_at TEXT");
    },
  },
  {
    version: 5,
    name: "reconcile-data-usage-counters",
    sql: "rebuild data usage counters from received uploads",
    apply(db) {
      db.exec("UPDATE data_usage SET permanent_bytes=0,rolling_bytes=0,records_count=0,reserved_bytes=0,updated_at=datetime('now')");
      db.exec(`
        INSERT INTO data_usage(software_id,slot_id,license_id,permanent_bytes,rolling_bytes,records_count,reserved_bytes,updated_at)
        SELECT u.software_id,u.slot_id,u.license_id,
          COALESCE(SUM(u.size),0),
          COALESCE(SUM(CASE WHEN u.received_at>=datetime('now','-24 hours') THEN u.size ELSE 0 END),0),
          COUNT(*),0,datetime('now')
        FROM data_uploads u
        WHERE u.status='received'
        GROUP BY u.software_id,u.slot_id,u.license_id
        ON CONFLICT(software_id,slot_id,license_id) DO UPDATE SET
          permanent_bytes=excluded.permanent_bytes,
          rolling_bytes=excluded.rolling_bytes,
          records_count=excluded.records_count,
          reserved_bytes=0,
          updated_at=excluded.updated_at
      `);
    },
  },
  {
    version: 6,
    name: "flat-file-resources",
    sql: "software file resources without release versioning",
    apply(db) {
      db.exec(`
        CREATE TABLE IF NOT EXISTS software_resources (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          software_id INTEGER NOT NULL REFERENCES software_slots(id) ON DELETE CASCADE,
          original_name TEXT NOT NULL,
          storage_name TEXT NOT NULL,
          storage_path TEXT NOT NULL,
          sha256 TEXT NOT NULL,
          size INTEGER NOT NULL,
          mime TEXT NOT NULL DEFAULT 'application/octet-stream',
          status TEXT NOT NULL DEFAULT 'ready' CHECK(status IN ('ready','deleted')),
          created_at TEXT NOT NULL
        )
      `);
      db.exec("CREATE INDEX IF NOT EXISTS idx_resources_scope ON software_resources(software_id, status)");
      db.exec(`
        INSERT OR IGNORE INTO software_resources(software_id,original_name,storage_name,storage_path,sha256,size,mime,status,created_at)
        SELECT r.software_id,f.original_name,f.storage_name,f.relative_path,f.sha256,f.size,f.mime,f.status,f.created_at
        FROM software_files f JOIN software_releases r ON r.id=f.release_id
        WHERE f.status='ready'
      `);
    },
  },
  {
    version: 7,
    name: "license-code-plaintext-encrypted",
    sql: "reversible encrypted license codes for admin search",
    apply(db) {
      const columns = db.prepare("PRAGMA table_info(license_codes)").all();
      if (!columns.some((column) => column.name === "code_encrypted")) db.exec("ALTER TABLE license_codes ADD COLUMN code_encrypted TEXT");
      db.exec("CREATE INDEX IF NOT EXISTS idx_license_codes_software ON license_codes(software_id, id DESC)");
    },
  },
  {
    version: 8,
    name: "per-license-data-store-and-announcements",
    sql: "overwrite/append data store and software announcements",
    apply(db) {
      db.exec(`
        CREATE TABLE IF NOT EXISTS data_store (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          software_id INTEGER NOT NULL REFERENCES software_slots(id) ON DELETE CASCADE,
          slot_id INTEGER NOT NULL REFERENCES data_slots(id) ON DELETE CASCADE,
          license_id INTEGER NOT NULL REFERENCES license_codes(id) ON DELETE CASCADE,
          value_encrypted TEXT NOT NULL,
          size INTEGER NOT NULL,
          sha256 TEXT NOT NULL,
          version INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          UNIQUE(software_id, slot_id, license_id)
        )
      `);
      db.exec("CREATE INDEX IF NOT EXISTS idx_data_store_scope ON data_store(software_id, slot_id, license_id)");
      const slotColumns = db.prepare("PRAGMA table_info(software_slots)").all();
      if (!slotColumns.some((column) => column.name === "announcement_text")) db.exec("ALTER TABLE software_slots ADD COLUMN announcement_text TEXT NOT NULL DEFAULT ''");
      if (!slotColumns.some((column) => column.name === "announcement_updated_at")) db.exec("ALTER TABLE software_slots ADD COLUMN announcement_updated_at TEXT");
    },
  },
  {
    version: 9,
    name: "encrypted-software-announcements",
    sql: "encrypted software announcements and data store scope index",
    apply(db) {
      const columns = db.prepare("PRAGMA table_info(software_slots)").all();
      if (!columns.some((column) => column.name === "announcement_encrypted")) db.exec("ALTER TABLE software_slots ADD COLUMN announcement_encrypted TEXT");
      db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_data_store_unique_scope ON data_store(software_id, slot_id, license_id)");
    },
  },
  {
    version: 10,
    name: "free-principals-ingest-and-maintenance",
    sql: "free principals, ingest events, upload sessions and audit metadata",
    apply(db) {
      db.exec(`
        CREATE TABLE IF NOT EXISTS free_users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          software_id INTEGER NOT NULL REFERENCES software_slots(id) ON DELETE CASCADE,
          license_id INTEGER NOT NULL UNIQUE REFERENCES license_codes(id) ON DELETE CASCADE,
          public_id TEXT NOT NULL UNIQUE,
          machine_hash TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
          created_at TEXT NOT NULL,
          last_seen_at TEXT NOT NULL,
          last_ip_hash TEXT,
          revoked_at TEXT,
          UNIQUE(software_id, machine_hash)
        );
      `);
      const hasColumn = (table, name) => db.prepare(`PRAGMA table_info(${table})`).all().some((column) => column.name === name);
      if (!hasColumn("software_slots", "access_mode")) db.exec("ALTER TABLE software_slots ADD COLUMN access_mode TEXT NOT NULL DEFAULT 'paid' CHECK(access_mode IN ('paid','free'))");
      if (!hasColumn("license_codes", "principal_type")) db.exec("ALTER TABLE license_codes ADD COLUMN principal_type TEXT NOT NULL DEFAULT 'paid' CHECK(principal_type IN ('paid','free'))");
      if (!hasColumn("client_sessions", "free_user_id")) db.exec("ALTER TABLE client_sessions ADD COLUMN free_user_id INTEGER REFERENCES free_users(id) ON DELETE SET NULL");
      if (!hasColumn("client_sessions", "revoke_reason")) db.exec("ALTER TABLE client_sessions ADD COLUMN revoke_reason TEXT");
      if (!hasColumn("client_sessions", "key_version")) db.exec("ALTER TABLE client_sessions ADD COLUMN key_version INTEGER");
      if (!hasColumn("data_uploads", "free_user_id")) db.exec("ALTER TABLE data_uploads ADD COLUMN free_user_id INTEGER REFERENCES free_users(id) ON DELETE SET NULL");
      if (!hasColumn("audit_log", "request_id")) db.exec("ALTER TABLE audit_log ADD COLUMN request_id TEXT");
      if (!hasColumn("audit_log", "reason")) db.exec("ALTER TABLE audit_log ADD COLUMN reason TEXT");
      if (!hasColumn("audit_log", "result")) db.exec("ALTER TABLE audit_log ADD COLUMN result TEXT NOT NULL DEFAULT 'success'");
      db.exec(`
        CREATE TABLE IF NOT EXISTS free_users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          software_id INTEGER NOT NULL REFERENCES software_slots(id) ON DELETE CASCADE,
          license_id INTEGER NOT NULL UNIQUE REFERENCES license_codes(id) ON DELETE CASCADE,
          public_id TEXT NOT NULL UNIQUE,
          machine_hash TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
          created_at TEXT NOT NULL,
          last_seen_at TEXT NOT NULL,
          last_ip_hash TEXT,
          revoked_at TEXT,
          UNIQUE(software_id, machine_hash)
        );
        CREATE INDEX IF NOT EXISTS idx_free_users_scope ON free_users(software_id, status, id DESC);
        CREATE INDEX IF NOT EXISTS idx_free_users_machine ON free_users(software_id, machine_hash);
        CREATE INDEX IF NOT EXISTS idx_client_sessions_free_user ON client_sessions(free_user_id, revoked_at, expires_at);
        CREATE INDEX IF NOT EXISTS idx_data_uploads_free_user ON data_uploads(free_user_id, received_at DESC);

        CREATE TABLE IF NOT EXISTS ingest_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          software_id INTEGER NOT NULL REFERENCES software_slots(id) ON DELETE CASCADE,
          slot_id INTEGER NOT NULL REFERENCES data_slots(id) ON DELETE CASCADE,
          license_id INTEGER NOT NULL REFERENCES license_codes(id) ON DELETE CASCADE,
          free_user_id INTEGER REFERENCES free_users(id) ON DELETE SET NULL,
          session_id TEXT REFERENCES client_sessions(id) ON DELETE SET NULL,
          event_id TEXT,
          mode TEXT NOT NULL CHECK(mode IN ('snapshot','event')),
          content_type TEXT NOT NULL DEFAULT 'application/json',
          schema_version INTEGER NOT NULL DEFAULT 1,
          header_json TEXT NOT NULL,
          content_encrypted TEXT NOT NULL,
          size INTEGER NOT NULL,
          sha256 TEXT NOT NULL,
          occurred_at TEXT,
          received_at TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'received' CHECK(status IN ('received','deleted')),
          UNIQUE(software_id, slot_id, license_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_ingest_events_scope ON ingest_events(software_id, slot_id, received_at DESC);
        CREATE INDEX IF NOT EXISTS idx_ingest_events_principal ON ingest_events(software_id, license_id, received_at DESC);

        CREATE TABLE IF NOT EXISTS resource_uploads (
          id TEXT PRIMARY KEY,
          software_id INTEGER NOT NULL REFERENCES software_slots(id) ON DELETE CASCADE,
          created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
          original_name TEXT NOT NULL,
          mime TEXT NOT NULL DEFAULT 'application/octet-stream',
          declared_size INTEGER NOT NULL,
          declared_sha256 TEXT,
          temp_path TEXT NOT NULL,
          received_bytes INTEGER NOT NULL DEFAULT 0,
          status TEXT NOT NULL DEFAULT 'receiving' CHECK(status IN ('receiving','completed','cancelled','failed')),
          expires_at TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_resource_uploads_expiry ON resource_uploads(status, expires_at);

        CREATE TABLE IF NOT EXISTS integration_clients (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL UNIQUE,
          token_hash TEXT NOT NULL UNIQUE,
          scopes_json TEXT NOT NULL DEFAULT '[]',
          software_id INTEGER REFERENCES software_slots(id) ON DELETE CASCADE,
          status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
          expires_at TEXT,
          created_at TEXT NOT NULL,
          last_used_at TEXT,
          revoked_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_integration_clients_scope ON integration_clients(software_id, status);
      `);
    },
  },
];

export function nowIso() {
  return new Date().toISOString();
}

function migrationChecksum(sql) {
  return createHash("sha256").update(sql).digest("hex");
}

export function migrateDatabase(db) {
  db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at TEXT NOT NULL)");
  const appliedRows = db.prepare("SELECT version,name,checksum FROM schema_migrations").all();
  const applied = new Set(appliedRows.map((row) => Number(row.version)));
  for (const appliedRow of appliedRows) {
    const migration = migrations.find((item) => item.version === Number(appliedRow.version));
    if (migration && appliedRow.checksum !== migrationChecksum(migration.sql)) throw new Error(`MIGRATION_CHECKSUM_MISMATCH:${appliedRow.version}`);
  }
  for (const migration of migrations) {
    if (applied.has(migration.version)) continue;
    db.exec("BEGIN IMMEDIATE");
    try {
      if (typeof migration.apply === "function") migration.apply(db);
      else db.exec(migration.sql);
      db.prepare("INSERT INTO schema_migrations(version,name,checksum,applied_at) VALUES(?,?,?,?)")
        .run(migration.version, migration.name, migrationChecksum(migration.sql), nowIso());
      db.exec("COMMIT");
    } catch (error) {
      try { db.exec("ROLLBACK"); } catch { /* preserve original error */ }
      throw error;
    }
  }
  return db.prepare("SELECT version,name,checksum,applied_at AS appliedAt FROM schema_migrations ORDER BY version").all();
}

export function openDatabase(filename) {
  mkdirSync(dirname(filename), { recursive: true });
  const db = new DatabaseSync(filename);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  migrateDatabase(db);
  return db;
}

export function getSetting(db, key, fallback) {
  const row = db.prepare("SELECT value FROM settings WHERE key = ?").get(key);
  if (!row) return fallback;
  try { return JSON.parse(row.value); } catch { return fallback; }
}

export function setSetting(db, key, value) {
  db.prepare(`INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`)
    .run(key, JSON.stringify(value), nowIso());
}

export function audit(db, { userId = null, action, objectType, objectId = null, metadata = {}, ipHash = null, softwareId = null, requestId = null, reason = null, result = "success" }) {
  const safeMetadata = metadata && typeof metadata === "object" ? metadata : {};
  const columns = db.prepare("PRAGMA table_info(audit_log)").all().map((column) => column.name);
  if (columns.includes("request_id")) {
    db.prepare("INSERT INTO audit_log(user_id,action,object_type,object_id,metadata,ip_hash,request_id,reason,result,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
      .run(userId, action, objectType, objectId == null ? null : String(objectId), JSON.stringify({ ...safeMetadata, ...(softwareId == null ? {} : { softwareId }) }), ipHash, requestId, reason, result, nowIso());
  } else {
    db.prepare("INSERT INTO audit_log(user_id,action,object_type,object_id,metadata,ip_hash,created_at) VALUES(?,?,?,?,?,?,?)")
      .run(userId, action, objectType, objectId == null ? null : String(objectId), JSON.stringify({ ...safeMetadata, ...(softwareId == null ? {} : { softwareId }) }), ipHash, nowIso());
  }
}

export function pruneNonces(db) {
  const now = nowIso();
  db.prepare("DELETE FROM nonce_cache WHERE expires_at < ?").run(now);
  db.prepare("DELETE FROM client_nonces WHERE expires_at < ?").run(now);
}

export function transaction(db, callback) {
  db.exec("BEGIN IMMEDIATE");
  try {
    const result = callback();
    db.exec("COMMIT");
    return result;
  } catch (error) {
    try { db.exec("ROLLBACK"); } catch { /* preserve original error */ }
    throw error;
  }
}

export { migrations };
