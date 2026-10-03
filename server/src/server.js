import Fastify from "fastify";
import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import argon2 from "argon2";
import {
  mkdirSync,
  readFileSync,
  writeFileSync,
  chmodSync,
  existsSync,
  renameSync,
  unlinkSync,
  rmSync,
  lstatSync,
  realpathSync,
  openSync,
  readSync,
  closeSync,
  statfsSync,
} from "node:fs";
import { dirname, join, resolve, relative } from "node:path";
import { randomBytes } from "node:crypto";
import os from "node:os";
import {
  openDatabase,
  nowIso,
  getSetting,
  setSetting,
  audit,
  pruneNonces,
  transaction,
} from "./db.js";
import {
  decryptAtRest,
  decryptClientPacket,
  encryptAtRest,
  encryptClientResponse,
  decryptSoftwarePacket,
  encryptSoftwarePacket,
  generateSoftwareKey,
  hmacHex,
  parseMasterSecret,
  randomToken,
  sha256,
  softwareKeyFingerprint,
} from "./crypto.js";

const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || 3000);
const DATABASE_PATH = process.env.SQLITE_DATABASE_PATH || "/opt/starlight/data/app.sqlite3";
const FILES_ROOT = resolve(process.env.FILES_ROOT || dirname(DATABASE_PATH) + "/files");
const DASHBOARD_ORIGIN = process.env.DASHBOARD_ORIGIN || "https://dashboard.example.com"; // TODO(需要补充)：生产环境在 /etc/jur10n/jur10n.env 里设 DASHBOARD_ORIGIN 为你的后台域名
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "owner";
const INITIAL_PASSWORD_FILE = process.env.INITIAL_ADMIN_PASSWORD_FILE || dirname(DATABASE_PATH) + "/initial-admin-password";
const SESSION_COOKIE = "jur10n_session";
const CSRF_COOKIE = "jur10n_csrf";
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_CLIENT_PACKET_BYTES = 256 * 1024;
const MAX_REPORT_BYTES = 128 * 1024;
const MAX_FILE_CHUNK_BYTES = 64 * 1024;
const FIXED_SLOT_QUOTA_BYTES = 200 * 1024;
const MAX_DATA_STORE_BYTES = FIXED_SLOT_QUOTA_BYTES;
const MAX_FILE_BYTES = Math.min(64 * 1024 * 1024, Math.max(1024, Number(process.env.MAX_FILE_BYTES || 64 * 1024 * 1024)));
const MAX_ADMIN_FILE_BODY_BYTES = Math.ceil(MAX_FILE_BYTES * 4 / 3) + 128 * 1024;
const CLIENT_TIMESTAMP_WINDOW_MS = Math.max(1000, Math.min(300000, Number(process.env.CLIENT_TIMESTAMP_WINDOW_MS || 60000)));
const CLIENT_HEARTBEAT_TIMEOUT_SECONDS = Math.max(30, Number(process.env.CLIENT_HEARTBEAT_TIMEOUT_SECONDS || 300));
const CODE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const MACHINE_PROOF_PATTERN = /^[A-Za-z0-9_-]{16,256}$/;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{16,256}$/;
const SLUG_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/;
const VAR_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ALLOWED_OPS = new Set(["login", "heartbeat", "pull_variables", "report", "ingest", "manifest", "file_chunk", "announcement"]);

class ApiError extends Error {
  constructor(code, status = 400) {
    super(code);
    this.code = code;
    this.status = status;
  }
}

function parseBool(value) {
  return value === true || value === 1 || value === "1";
}

function clientCodeHash(masterSecret, code) {
  return Buffer.from(hmacHex(masterSecret, `license:${code}`), "hex");
}

function hashToken(masterSecret, token) {
  return hmacHex(masterSecret, `session:${token}`);
}

function hashIp(masterSecret, ip) {
  return hmacHex(masterSecret, `ip:${ip || "unknown"}`);
}

function machineHash(rawKey, proof) {
  return hmacHex(rawKey, `machine:${proof}`);
}

function stableMachineHash(masterSecret, softwareId, proof) {
  return hmacHex(masterSecret, `machine-binding:v2:${softwareId}:${proof}`);
}

function principalLabel(row) {
  return row?.principal_type === "free" ? (row.public_id || null) : (row.public_id || null);
}

function getMachineProofHashes(db, masterSecret, software, proof, currentRawKey) {
  if (typeof proof !== "string" || !MACHINE_PROOF_PATTERN.test(proof)) return [];
  const hashes = [stableMachineHash(masterSecret, software.id, proof), machineHash(currentRawKey, proof)];
  const rows = db.prepare("SELECT encrypted_key FROM software_keys WHERE software_id=?").all(software.id);
  for (const row of rows) {
    try { hashes.push(machineHash(decodeStoredSoftwareKey(masterSecret, row.encrypted_key), proof)); } catch { /* ignore damaged historical keys */ }
  }
  return [...new Set(hashes)];
}

function validIso(value) {
  if (value == null || value === "") return null;
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) throw new ApiError("INVALID_DATE");
  return date.toISOString();
}

function safeLimit(value, fallback = 50, max = 100) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? Math.min(parsed, max) : fallback;
}

function jsonBodySize(value) {
  return Buffer.byteLength(JSON.stringify(value ?? null), "utf8");
}

function publicUser(user) {
  return { id: user.id, username: user.username, role: user.role, mustChangePassword: Boolean(user.must_change_password) };
}

function setSecureCookies(reply, sessionToken, csrfToken) {
  reply.setCookie(SESSION_COOKIE, sessionToken, { httpOnly: true, secure: true, sameSite: "strict", path: "/", maxAge: SESSION_TTL_MS / 1000 });
  reply.setCookie(CSRF_COOKIE, csrfToken, { httpOnly: false, secure: true, sameSite: "strict", path: "/", maxAge: SESSION_TTL_MS / 1000 });
}

function clearAuthCookies(reply) {
  reply.clearCookie(SESSION_COOKIE, { path: "/" });
  reply.clearCookie(CSRF_COOKIE, { path: "/" });
}

function checkOrigin(request) {
  const origin = request.headers.origin;
  return !origin || origin === DASHBOARD_ORIGIN;
}

function getClientIp(request) {
  return request.ip || request.headers["x-forwarded-for"]?.split(",")[0]?.trim() || "unknown";
}

function createRateLimiter(db) {
  const buckets = new Map();
  return function rateLimit(request) {
    const limit = Math.max(1, Math.min(10000, Number(getSetting(db, "client_rate_limit_per_minute", 30)) || 30));
    const ip = getClientIp(request);
    const windowStart = Math.floor(Date.now() / 60000) * 60000;
    const current = buckets.get(ip);
    if (!current || current.windowStart !== windowStart) {
      buckets.set(ip, { windowStart, count: 1 });
      if (buckets.size > 10000) for (const [key, bucket] of buckets) if (bucket.windowStart !== windowStart) buckets.delete(key);
      return { allowed: true, limit, remaining: limit - 1 };
    }
    current.count += 1;
    return { allowed: current.count <= limit, limit, remaining: Math.max(0, limit - current.count) };
  };
}

function keyWithinWindow(row, at = Date.now()) {
  if (row.not_before && new Date(row.not_before).getTime() > at) return false;
  if (row.not_after && new Date(row.not_after).getTime() <= at) return false;
  return true;
}

function getActiveSoftwareKey(db, masterSecret, softwareId, version = null, includeRevoked = false) {
  let row;
  if (version != null) {
    row = db.prepare(`SELECT * FROM software_keys WHERE software_id=? AND version=?${includeRevoked ? "" : " AND status='active'"}`).get(softwareId, Number(version));
  } else {
    row = db.prepare(`SELECT * FROM software_keys WHERE software_id=? ${includeRevoked ? "" : "AND status='active'"} ORDER BY version DESC LIMIT 1`).get(softwareId);
  }
  if (!row || (!includeRevoked && row.status !== "active") || !keyWithinWindow(row)) throw new ApiError("KEY_UNAVAILABLE", 503);
  let rawKey;
  try {
    rawKey = decodeStoredSoftwareKey(masterSecret, row.encrypted_key);
  } catch { throw new ApiError("KEY_UNAVAILABLE", 503); }
  return { row, rawKey };
}

function softwarePublic(dbOrRow, maybeRow) {
  const db = maybeRow ? dbOrRow : null;
  const row = maybeRow || dbOrRow;
  const result = {
    id: row.id,
    slug: row.slug,
    name: row.name,
    description: row.description,
    status: row.status,
    machineCheck: Boolean(row.machine_check),
    ipCheck: Boolean(row.ip_check),
    ipChangePolicy: row.ip_change_policy,
    heartbeatTimeout: row.heartbeat_timeout,
    sessionTtl: row.session_ttl,
    accessMode: row.access_mode || "paid",
    isFree: (row.access_mode || "paid") === "free",
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
  if (!db) return result;
  const activeKey = db.prepare("SELECT version,fingerprint FROM software_keys WHERE software_id=? AND status='active' ORDER BY version DESC LIMIT 1").get(row.id);
  const now = nowIso();
  const hourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  Object.assign(result, {
    protocolVersion: "jur10n-client-v2",
    currentKeyVersion: activeKey?.version,
    keyFingerprint: activeKey?.fingerprint,
    licenseCount: Number(db.prepare("SELECT COUNT(*) AS count FROM license_codes WHERE software_id=?").get(row.id).count),
    activeLicenseCount: Number(db.prepare("SELECT COUNT(*) AS count FROM license_codes WHERE software_id=? AND status='active' AND (expires_at IS NULL OR expires_at>?)").get(row.id, now).count),
    variableCount: Number(db.prepare("SELECT COUNT(*) AS count FROM software_variables WHERE software_id=? AND enabled=1").get(row.id).count),
    dataSlotCount: Number(db.prepare("SELECT COUNT(*) AS count FROM data_slots WHERE software_id=? AND enabled=1").get(row.id).count),
    activeSessions: Number(db.prepare("SELECT COUNT(*) AS count FROM client_sessions WHERE software_id=? AND revoked_at IS NULL AND expires_at>? AND last_heartbeat_at>?").get(row.id, now, new Date(Date.now() - Number(row.heartbeat_timeout || 300) * 1000).toISOString()).count),
    qps: Number(db.prepare("SELECT COUNT(*) AS count FROM data_uploads WHERE software_id=? AND received_at>=?").get(row.id, hourAgo).count) / 3600,
    announcementUpdatedAt: row.announcement_updated_at || null,
  });
  return result;
}

function decodeStoredSoftwareKey(masterSecret, encryptedKey) {
  let value;
  try { value = decryptAtRest(masterSecret, encryptedKey); } catch { throw new ApiError("KEY_UNAVAILABLE", 503); }
  let raw;
  if (typeof value === "string") raw = Buffer.from(value, "base64url");
  else if (Buffer.isBuffer(value)) raw = Buffer.from(value);
  else if (value && value.type === "Buffer" && Array.isArray(value.data)) raw = Buffer.from(value.data);
  else if (value && typeof value.key === "string") raw = Buffer.from(value.key, "base64url");
  else raw = Buffer.alloc(0);
  if (raw.length !== 32) throw new ApiError("KEY_UNAVAILABLE", 503);
  return raw;
}

function parseStrictBase64(value) {
  if (typeof value !== "string" || !value || value.length % 4 === 1 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) throw new ApiError("INVALID_FILE");
  const normalized = value.replace(/=+$/, "");
  const decoded = Buffer.from(value, "base64");
  if (!decoded.length || decoded.toString("base64").replace(/=+$/, "") !== normalized) throw new ApiError("INVALID_FILE");
  return decoded;
}

function keyPublic(row) {
  return { id: row.id, softwareId: row.software_id, version: row.version, fingerprint: row.fingerprint, status: row.status, notBefore: row.not_before, notAfter: row.not_after, createdAt: row.created_at, revokedAt: row.revoked_at, exportedAt: row.exported_at };
}

function licensePublic(row, deviceCount = 0) {
  return { id: row.id, publicId: row.public_id, status: row.status, expiresAt: row.expires_at, maxDevices: row.max_devices, deviceCount, note: row.note, createdAt: row.created_at, updatedAt: row.updated_at, lastUsedAt: row.last_used_at };
}

function requireSlug(value) {
  if (typeof value !== "string" || !SLUG_PATTERN.test(value)) throw new ApiError("INVALID_SOFTWARE", 404);
  return value;
}

function findSoftware(db, slug) {
  const row = db.prepare("SELECT * FROM software_slots WHERE slug=?").get(requireSlug(slug));
  if (!row) throw new ApiError("NOT_FOUND", 404);
  return row;
}

function ensureSoftwareKey(db, masterSecret, softwareId) {
  const existing = db.prepare("SELECT * FROM software_keys WHERE software_id=? AND status='active' ORDER BY version DESC LIMIT 1").get(softwareId);
  if (existing) return existing;
  const rawKey = generateSoftwareKey();
  const now = nowIso();
  db.prepare("INSERT INTO software_keys(software_id,version,encrypted_key,fingerprint,status,not_before,created_at) VALUES(?,?,?,?,?,?,?)")
    .run(softwareId, 1, encryptAtRest(masterSecret, rawKey.toString("base64url")), softwareKeyFingerprint(rawKey), "active", now, now);
  return db.prepare("SELECT * FROM software_keys WHERE software_id=? AND version=1").get(softwareId);
}

async function ensureInitialAdmin(db) {
  const row = db.prepare("SELECT id FROM users LIMIT 1").get();
  if (row) return;
  const password = process.env.ADMIN_INITIAL_PASSWORD || randomToken(18);
  const now = nowIso();
  const passwordHash = await argon2.hash(password, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
  db.prepare("INSERT INTO users(username,password_hash,role,must_change_password,created_at,updated_at) VALUES(?,?,?,?,?,?)")
    .run(ADMIN_USERNAME, passwordHash, "owner", 1, now, now);
  mkdirSync(dirname(INITIAL_PASSWORD_FILE), { recursive: true });
  writeFileSync(INITIAL_PASSWORD_FILE, `${password}\n`, { mode: 0o600 });
  chmodSync(INITIAL_PASSWORD_FILE, 0o600);
}

function encryptedFailure(rawKey, slot, version, code, status = 400) {
  return encryptSoftwarePacket(rawKey, slot, version, { ok: false, status, error: code, timestamp: Date.now() }, "response");
}

function encryptedSuccess(rawKey, slot, version, data, status = 200) {
  return encryptSoftwarePacket(rawKey, slot, version, { ok: true, status, data, timestamp: Date.now() }, "response");
}

function validateV2Envelope(payload, keyVersion) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new ApiError("INVALID_REQUEST");
  if (payload.protocol !== "jur10n-client-v2") throw new ApiError("INVALID_PROTOCOL");
  if (!Number.isSafeInteger(payload.key_version) || payload.key_version < 1 || (keyVersion != null && payload.key_version !== Number(keyVersion))) throw new ApiError("INVALID_KEY_VERSION");
  if (!Number.isSafeInteger(payload.timestamp) || Math.abs(Date.now() - payload.timestamp) > CLIENT_TIMESTAMP_WINDOW_MS) throw new ApiError("TIMESTAMP_INVALID");
  if (typeof payload.nonce !== "string" || !NONCE_PATTERN.test(payload.nonce)) throw new ApiError("INVALID_REQUEST");
  if (!ALLOWED_OPS.has(payload.op)) throw new ApiError("INVALID_OPERATION");
  if (payload.machine_proof != null && (typeof payload.machine_proof !== "string" || !MACHINE_PROOF_PATTERN.test(payload.machine_proof))) throw new ApiError("INVALID_MACHINE_PROOF");
}

function findV2KeyForRequest(db, masterSecret, software, body, requestedVersion) {
  const rows = requestedVersion != null
    ? db.prepare("SELECT * FROM software_keys WHERE software_id=? AND version=?").all(software.id, Number(requestedVersion))
    : db.prepare("SELECT * FROM software_keys WHERE software_id=? AND status='active' ORDER BY version DESC").all(software.id);
  for (const row of rows) {
    try {
      if (row.status !== "active" || !keyWithinWindow(row)) continue;
      let key = decodeStoredSoftwareKey(masterSecret, row.encrypted_key);
      if (key.length !== 32) continue;
      const payload = decryptSoftwarePacket(key, software.slug, row.version, body, "request");
      return { row, rawKey: key, payload };
    } catch { /* try the next active version */ }
  }
  throw new ApiError("INVALID_REQUEST");
}

function claimClientNonce(db, softwareId, sessionId, nonce) {
  if (typeof nonce !== "string" || !NONCE_PATTERN.test(nonce)) throw new ApiError("INVALID_REQUEST");
  pruneNonces(db);
  const result = db.prepare("INSERT OR IGNORE INTO client_nonces(software_id,session_id,nonce,expires_at,created_at) VALUES(?,?,?,?,?)")
    .run(softwareId, sessionId, nonce, new Date(Date.now() + 5 * 60 * 1000).toISOString(), nowIso());
  if (Number(result.changes) !== 1) throw new ApiError("REPLAY_DETECTED", 409);
}

function findLicenseByCode(db, software, masterSecret, code) {
  if (typeof code !== "string" || !CODE_PATTERN.test(code)) throw new ApiError("INVALID_CREDENTIALS", 401);
  const row = db.prepare("SELECT * FROM license_codes WHERE software_id=? AND code_hash=? LIMIT 1").get(software.id, clientCodeHash(masterSecret, code));
  if (!row || row.status !== "active") throw new ApiError("INVALID_CREDENTIALS", 401);
  if (row.expires_at && new Date(row.expires_at).getTime() <= Date.now()) throw new ApiError("LICENSE_EXPIRED", 401);
  return row;
}

function revokeLicenseSessions(db, licenseId, reason) {
  const now = nowIso();
  return db.prepare("UPDATE client_sessions SET revoked_at=COALESCE(revoked_at,?),revoke_reason=COALESCE(revoke_reason,?) WHERE license_id=? AND revoked_at IS NULL")
    .run(now, reason, licenseId);
}

function findOrCreateFreeUser(db, masterSecret, software, machineProof, ipHash) {
  if (typeof machineProof !== "string" || !MACHINE_PROOF_PATTERN.test(machineProof)) throw new ApiError("MACHINE_PROOF_REQUIRED", 403);
  const machine = stableMachineHash(masterSecret, software.id, machineProof);
  const existing = db.prepare(`SELECT f.*,l.status AS license_status,l.expires_at,l.max_devices,l.public_id AS license_public_id
    FROM free_users f JOIN license_codes l ON l.id=f.license_id
    WHERE f.software_id=? AND f.machine_hash=?`).get(software.id, machine);
  if (existing) {
    if (existing.status !== "active" || existing.license_status !== "active") throw new ApiError("INVALID_CREDENTIALS", 401);
    const now = nowIso();
    db.prepare("UPDATE free_users SET last_seen_at=?,last_ip_hash=? WHERE id=?").run(now, ipHash, existing.id);
    return { freeUser: existing, license: db.prepare("SELECT * FROM license_codes WHERE id=?").get(existing.license_id), machineHash: machine };
  }
  const now = nowIso();
  const internalCode = `FREE-${randomToken(24)}`;
  const publicId = `free-${randomToken(9)}`;
  const licenseResult = db.prepare(`INSERT INTO license_codes(software_id,code_hash,code_encrypted,public_id,status,expires_at,max_devices,note,created_at,updated_at,principal_type)
    VALUES(?,?,?,?,?,?,?,?,?,?,?)`).run(software.id, clientCodeHash(masterSecret, internalCode), encryptAtRest(masterSecret, { free: true }), publicId, "active", null, 1, "free machine principal", now, now, "free");
  const licenseId = Number(licenseResult.lastInsertRowid);
  const userResult = db.prepare(`INSERT INTO free_users(software_id,license_id,public_id,machine_hash,status,created_at,last_seen_at,last_ip_hash)
    VALUES(?,?,?,?,?,?,?,?)`).run(software.id, licenseId, publicId, machine, "active", now, now, ipHash);
  return { freeUser: db.prepare("SELECT * FROM free_users WHERE id=?").get(Number(userResult.lastInsertRowid)), license: db.prepare("SELECT * FROM license_codes WHERE id=?").get(licenseId), machineHash: machine };
}

function validateIpPolicy(software, binding, ipHash, forLogin = false) {
  if (!software.ip_check) return;
  if (!binding?.ip_hash || binding.ip_hash === ipHash) return;
  if (software.ip_change_policy === "allow" || software.ip_change_policy === "update") return;
  throw new ApiError("IP_MISMATCH", 403);
}

function loadSession(db, masterSecret, software, payload, ipHash, machineProofHashes = []) {
  if (typeof payload.session_token !== "string" || !NONCE_PATTERN.test(payload.session_token)) throw new ApiError("SESSION_REQUIRED", 401);
  if (payload.session_id != null && (typeof payload.session_id !== "string" || payload.session_id.length < 16 || payload.session_id.length > 128)) throw new ApiError("INVALID_REQUEST");
  const tokenHash = hashToken(masterSecret, payload.session_token);
  const found = payload.session_id
    ? db.prepare("SELECT * FROM client_sessions WHERE id=? AND software_id=? AND token_hash=?").get(payload.session_id, software.id, tokenHash)
    : db.prepare("SELECT * FROM client_sessions WHERE software_id=? AND token_hash=?").get(software.id, tokenHash);
  if (!found || found.revoked_at) throw new ApiError("SESSION_REVOKED", 401);
  if (new Date(found.expires_at).getTime() <= Date.now()) throw new ApiError("SESSION_EXPIRED", 401);
  if (Date.now() - new Date(found.last_heartbeat_at).getTime() > Number(software.heartbeat_timeout || CLIENT_HEARTBEAT_TIMEOUT_SECONDS) * 1000) throw new ApiError("SESSION_INACTIVE", 401);
  const license = db.prepare("SELECT * FROM license_codes WHERE id=? AND software_id=?").get(found.license_id, software.id);
  if (!license || license.status !== "active") throw new ApiError("INVALID_CREDENTIALS", 401);
  if (license.expires_at && new Date(license.expires_at).getTime() <= Date.now()) throw new ApiError("LICENSE_EXPIRED", 401);
  if (found.free_user_id) {
    const freeUser = db.prepare("SELECT * FROM free_users WHERE id=? AND software_id=?").get(found.free_user_id, software.id);
    if (!freeUser || freeUser.status !== "active") throw new ApiError("INVALID_CREDENTIALS", 401);
  }
  const binding = db.prepare("SELECT * FROM license_bindings WHERE license_id=?").get(found.license_id);
  if (!binding) throw new ApiError("MACHINE_MISMATCH", 403);
  if (software.machine_check && (!machineProofHashes.length || !machineProofHashes.includes(found.machine_hash))) throw new ApiError("MACHINE_MISMATCH", 403);
  validateIpPolicy(software, binding, ipHash);
  const freeUser = found.free_user_id ? db.prepare("SELECT * FROM free_users WHERE id=?").get(found.free_user_id) : null;
  return { session: found, binding, license, freeUser };
}

function ensureStorageAvailable() {
  const lowWater = Number(process.env.MIN_FREE_BYTES || 256 * 1024 * 1024);
  try {
    const stats = statfsSync(FILES_ROOT);
    const free = Number(stats.bavail) * Number(stats.bsize);
    const inodesFree = Number(stats.favail);
    const inodesTotal = Number(stats.files);
    const inodeWater = Number(process.env.MIN_FREE_INODES || 128);
    if (free < lowWater || (Number.isFinite(inodesFree) && Number.isFinite(inodesTotal) && inodesTotal > 0 && inodesFree < inodeWater)) throw new ApiError("STORAGE_LIMIT", 507);
  } catch (error) {
    if (error instanceof ApiError) throw error;
  }
}

function readDataSlot(db, software, slug) {
  if (typeof slug !== "string" || !/^[a-z0-9][a-z0-9-]{0,62}$/.test(slug)) throw new ApiError("INVALID_DATA_SLOT");
  const row = db.prepare("SELECT * FROM data_slots WHERE software_id=? AND slug=? AND enabled=1").get(software.id, slug);
  if (!row) throw new ApiError("DATA_SLOT_NOT_FOUND", 404);
  return row;
}

function reserveAndStoreUpload(db, masterSecret, software, license, session, machine, slot, data, ipHash, inTransaction = false) {
  const serialized = JSON.stringify(data ?? null);
  if (typeof serialized !== "string") throw new ApiError("INVALID_PAYLOAD");
  const size = Buffer.byteLength(serialized, "utf8");
  const globalSettings = getSetting(db, "receive_settings", { enabled: true, maxPayloadBytes: MAX_REPORT_BYTES });
  if (!globalSettings.enabled) throw new ApiError("RECEIVING_DISABLED", 403);
  if (size > Math.min(MAX_REPORT_BYTES, Number(globalSettings.maxPayloadBytes) || MAX_REPORT_BYTES)) throw new ApiError("PAYLOAD_TOO_LARGE", 413);
  ensureStorageAvailable();
  const operation = () => {
    const current = db.prepare("SELECT * FROM data_usage WHERE software_id=? AND slot_id=? AND license_id=?")
      .get(software.id, slot.id, license.id);
    const permanent = Number(current?.permanent_bytes || 0);
    if (permanent + size > FIXED_SLOT_QUOTA_BYTES) throw new ApiError("QUOTA_EXCEEDED", 413);
    const now = nowIso();
    const encrypted = encryptAtRest(masterSecret, data);
    const digest = sha256(serialized);
    const result = db.prepare(`INSERT INTO data_uploads(software_id,slot_id,license_id,session_id,machine_hash,payload_encrypted,size,sha256,received_at,status)
      VALUES(?,?,?,?,?,?,?,?,?,'received')`).run(software.id, slot.id, license.id, session.id, machine, encrypted, size, digest, now);
    db.prepare(`INSERT INTO data_usage(software_id,slot_id,license_id,permanent_bytes,rolling_bytes,records_count,reserved_bytes,updated_at)
      VALUES(?,?,?,?,?,0,0,?) ON CONFLICT(software_id,slot_id,license_id) DO UPDATE SET permanent_bytes=permanent_bytes+excluded.permanent_bytes, records_count=records_count+1, updated_at=excluded.updated_at`)
      .run(software.id, slot.id, license.id, size, 0, now);
    db.prepare("UPDATE license_codes SET last_used_at=?,updated_at=? WHERE id=?").run(now, now, license.id);
    return { id: result.lastInsertRowid, accepted: true, receivedAt: now, size, sha256: digest, quotaBytes: FIXED_SLOT_QUOTA_BYTES, usedBytes: permanent + size };
  };
  return inTransaction ? operation() : transaction(db, operation);
}

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function appendValues(current, incoming) {
  if (Array.isArray(current) && Array.isArray(incoming)) return [...current, ...incoming];
  if (isPlainObject(current) && isPlainObject(incoming)) return { ...current, ...incoming };
  if (typeof current === "string" && typeof incoming === "string") return current + incoming;
  throw new ApiError("INVALID_APPEND");
}

function normalizeLicensePrefix(value) {
  return typeof value === "string" ? value.toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 12) : "";
}

function generatedLicenseCode(prefix = "") {
  const body = randomBytes(16).toString("hex").toUpperCase();
  const normalized = normalizeLicensePrefix(prefix);
  return normalized ? `${normalized}-${body}` : body;
}

function dataStorePublic(masterSecret, row, { includeValue = true } = {}) {
  let value = null;
  if (includeValue) {
    try { value = decryptAtRest(masterSecret, row.value_encrypted); } catch { throw new ApiError("INVALID_PAYLOAD", 500); }
  }
  return {
    id: row.id,
    softwareId: row.software_id,
    slotId: row.slot_id,
    slotSlug: row.slot_slug,
    licenseId: row.license_id,
    publicId: row.public_id || null,
    value,
    valueAvailable: includeValue,
    size: row.size,
    sha256: row.sha256,
    version: row.version,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function announcementPublic(software, masterSecret) {
  let announcement = software.announcement_text || "";
  if (software.announcement_encrypted) {
    try { announcement = decryptAtRest(masterSecret, software.announcement_encrypted); } catch { announcement = ""; }
  }
  return { softwareSlot: software.slug, announcement: typeof announcement === "string" ? announcement : "", updatedAt: software.announcement_updated_at || null };
}

function migrateAnnouncementAtRest(db, masterSecret) {
  const rows = db.prepare("SELECT id,announcement_text,announcement_encrypted FROM software_slots WHERE announcement_encrypted IS NULL AND announcement_text IS NOT NULL AND announcement_text<>''").all();
  if (!rows.length) return;
  transaction(db, () => {
    for (const row of rows) {
      db.prepare("UPDATE software_slots SET announcement_encrypted=?,announcement_text='' WHERE id=? AND announcement_encrypted IS NULL")
        .run(encryptAtRest(masterSecret, row.announcement_text), row.id);
    }
  });
}

function writeDataStore(db, masterSecret, software, licenseId, slot, data, mode, inTransaction = false, context = {}) {
  if (mode !== "overwrite" && mode !== "append") throw new ApiError("INVALID_MODE");
  const operation = () => {
    const existing = db.prepare("SELECT * FROM data_store WHERE software_id=? AND slot_id=? AND license_id=?")
      .get(software.id, slot.id, licenseId);
    let value = data ?? null;
    if (mode === "append" && existing) {
      let current;
      try { current = decryptAtRest(masterSecret, existing.value_encrypted); } catch { throw new ApiError("INVALID_PAYLOAD"); }
      value = appendValues(current, value);
    }
    let serialized;
    try { serialized = JSON.stringify(value); } catch { throw new ApiError("INVALID_PAYLOAD"); }
    if (typeof serialized !== "string") throw new ApiError("INVALID_PAYLOAD");
    const size = Buffer.byteLength(serialized, "utf8");
    const receiveSettings = getSetting(db, "receive_settings", { enabled: true, maxPayloadBytes: MAX_REPORT_BYTES });
    if (!receiveSettings.enabled) throw new ApiError("RECEIVING_DISABLED", 403);
    const maxPayloadBytes = Math.min(MAX_REPORT_BYTES, Number(receiveSettings.maxPayloadBytes) || MAX_REPORT_BYTES);
    if (size > maxPayloadBytes || size > MAX_DATA_STORE_BYTES) throw new ApiError("PAYLOAD_TOO_LARGE", 413);
    ensureStorageAvailable();
    const now = nowIso();
    const digest = sha256(serialized);
    const encrypted = encryptAtRest(masterSecret, value);
    let dataStoreId;
    let version;
    if (existing) {
      version = Number(existing.version) + 1;
      db.prepare("UPDATE data_store SET value_encrypted=?,size=?,sha256=?,version=?,updated_at=? WHERE id=? AND software_id=? AND slot_id=? AND license_id=?")
        .run(encrypted, size, digest, version, now, existing.id, software.id, slot.id, licenseId);
      dataStoreId = existing.id;
    } else {
      version = 1;
      const result = db.prepare("INSERT INTO data_store(software_id,slot_id,license_id,value_encrypted,size,sha256,version,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)")
        .run(software.id, slot.id, licenseId, encrypted, size, digest, version, now, now);
      dataStoreId = Number(result.lastInsertRowid);
    }
    let uploadId = null;
    if (context.recordHistory) {
      const result = db.prepare(`INSERT INTO data_uploads(software_id,slot_id,license_id,free_user_id,session_id,machine_hash,payload_encrypted,size,sha256,received_at,status)
        VALUES(?,?,?,?,?,?,?,?,?,?,'received')`).run(software.id, slot.id, licenseId, context.freeUserId || null, context.sessionId || null, context.machineHash || null, encrypted, size, digest, now);
      uploadId = Number(result.lastInsertRowid);
    }
    db.prepare("UPDATE license_codes SET last_used_at=?,updated_at=? WHERE id=? AND software_id=?").run(now, now, licenseId, software.id);
    return { id: uploadId || dataStoreId, dataStoreId, accepted: true, mode: existing ? mode : "created", size, sha256: digest, version, quotaBytes: MAX_DATA_STORE_BYTES, usedBytes: size, updatedAt: now };
  };
  return inTransaction ? operation() : transaction(db, operation);
}

function findDataSlot(db, software, slug, includeDisabled = false) {
  if (typeof slug !== "string" || !/^[a-z0-9][a-z0-9-]{0,62}$/.test(slug)) throw new ApiError("INVALID_DATA_SLOT");
  const row = db.prepare(`SELECT * FROM data_slots WHERE software_id=? AND slug=?${includeDisabled ? "" : " AND enabled=1"}`).get(software.id, slug);
  if (!row) throw new ApiError("DATA_SLOT_NOT_FOUND", 404);
  return row;
}

function listDataStoreRows(db, masterSecret, software, query = {}) {
  const params = [software.id];
  let where = "WHERE s.software_id=?";
  if (query.licenseId != null && query.licenseId !== "") {
    const licenseId = Number(query.licenseId);
    if (!Number.isSafeInteger(licenseId) || licenseId < 1) throw new ApiError("INVALID_LICENSE", 400);
    where += " AND s.license_id=?";
    params.push(licenseId);
  }
  const slot = query.slot ?? query.data_slot;
  if (slot != null && slot !== "") {
    if (typeof slot !== "string" || !/^[a-z0-9][a-z0-9-]{0,62}$/.test(slot)) throw new ApiError("INVALID_DATA_SLOT");
    where += " AND d.slug=?";
    params.push(slot);
  }
  const rows = db.prepare(`SELECT s.*,d.slug AS slot_slug,l.public_id
    FROM data_store s JOIN data_slots d ON d.id=s.slot_id AND d.software_id=s.software_id
    JOIN license_codes l ON l.id=s.license_id AND l.software_id=s.software_id
    ${where} ORDER BY s.updated_at DESC,s.id DESC`).all(...params);
  return rows.map((row) => dataStorePublic(masterSecret, row));
}

function safeResourcePath(file) {
  const root = resolve(FILES_ROOT);
  const storagePath = String(file.storage_path || "");
  if (!storagePath || storagePath.includes("\\") || storagePath.startsWith("/")) throw new ApiError("FILE_NOT_FOUND", 404);
  const target = resolve(root, storagePath);
  if (relative(root, target).startsWith("..")) throw new ApiError("FILE_NOT_FOUND", 404);
  if (!existsSync(target)) throw new ApiError("FILE_NOT_FOUND", 404);
  const stat = lstatSync(target);
  if (stat.isSymbolicLink() || !stat.isFile()) throw new ApiError("FILE_NOT_FOUND", 404);
  const actual = realpathSync(target);
  if (relative(root, actual).startsWith("..")) throw new ApiError("FILE_NOT_FOUND", 404);
  return target;
}

function publicResource(row) {
  return { id: row.id, softwareId: row.software_id, originalName: row.original_name, sha256: row.sha256, size: row.size, mime: row.mime, status: row.status, createdAt: row.created_at };
}

function publicUpload(row, { includeSensitive = false } = {}) {
  return {
    id: row.id,
    softwareId: row.software_id,
    slotId: row.slot_id,
    slotSlug: row.slot_slug || row.data_slot || null,
    dataSlot: row.slot_slug || row.data_slot || null,
    licenseId: row.license_id,
    freeUserId: row.free_user_id || null,
    publicId: row.public_id || null,
    sessionId: row.session_id,
    machineHash: includeSensitive ? (row.machine_hash || null) : null,
    size: row.size,
    sha256: row.sha256,
    receivedAt: row.received_at,
    status: row.status,
  };
}

function parseBase64Content(value) {
  return parseStrictBase64(value);
}

export async function buildApp(options = {}) {
  const masterSecret = options.masterSecret || parseMasterSecret(process.env.MASTER_SECRET);
  const db = options.db || openDatabase(options.databasePath || DATABASE_PATH);
  mkdirSync(FILES_ROOT, { recursive: true });
  if (!getSetting(db, "client_rate_limit_per_minute", null)) setSetting(db, "client_rate_limit_per_minute", 30);
  if (!getSetting(db, "receive_settings", null)) setSetting(db, "receive_settings", { enabled: true, maxPayloadBytes: MAX_REPORT_BYTES });
  if (!getSetting(db, "protocol_version", null)) setSetting(db, "protocol_version", "jur10n-client-v2");
  const legacy = db.prepare("SELECT * FROM software_slots WHERE slug='legacy'").get();
  if (legacy) ensureSoftwareKey(db, masterSecret, legacy.id);
  if (!options.skipInitialAdmin) await ensureInitialAdmin(db);
  migrateAnnouncementAtRest(db, masterSecret);

  const app = Fastify({ logger: options.logger ?? true, trustProxy: ["127.0.0.1", "::1"], bodyLimit: MAX_ADMIN_FILE_BODY_BYTES, rewriteUrl(request) {
    return request.url.replace(/^\/api\/admin\/software-slots(?=\/|\?|$)/, "/api/admin/software");
  } });
  app.decorate("db", db);
  app.decorate("masterSecret", masterSecret);
  app.decorate("clientRateLimit", createRateLimiter(db));
  app.decorate("loginBuckets", new Map());
  app.decorateRequest("auth", null);
  await app.register(cookie);
  await app.register(cors, { origin: DASHBOARD_ORIGIN, credentials: true, methods: ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"] });
  app.addContentTypeParser("application/octet-stream", { parseAs: "buffer" }, (_request, body, done) => done(null, body));

  app.get("/healthz", async () => ({ ok: true, service: "jur10n-server", time: nowIso() }));

  // v2 encrypted client endpoint. key_version is accepted in a header/query
  // because it is needed to select the AES key before decrypting the body.
  app.post("/api/v2/client/:software_slot", async (request, reply) => {
    let software;
    try { software = findSoftware(db, request.params.software_slot); } catch (error) {
      if (error instanceof ApiError && error.status === 404) return reply.code(404).send({ error: "NOT_FOUND" });
      throw error;
    }
    const rate = app.clientRateLimit(request);
    const requestedVersion = request.headers["x-key-version"] || request.query?.key_version || null;
    let response;
    let responseKey;
    try {
      if (!rate.allowed) {
        responseKey = getActiveSoftwareKey(db, masterSecret, software.id);
        response = encryptedFailure(responseKey.rawKey, software.slug, responseKey.row.version, "RATE_LIMITED", 429);
      } else {
        if (software.status !== "active") throw new ApiError("SOFTWARE_DISABLED", 403);
        if (String(request.headers["content-type"] || "").toLowerCase().split(";")[0] !== "application/octet-stream") throw new ApiError("INVALID_REQUEST");
        const body = Buffer.isBuffer(request.body) ? request.body : Buffer.from(request.body || "");
        if (!body.length || body.length > MAX_CLIENT_PACKET_BYTES) throw new ApiError("INVALID_REQUEST");
        const parsed = findV2KeyForRequest(db, masterSecret, software, body, requestedVersion);
        responseKey = parsed;
        validateV2Envelope(parsed.payload, requestedVersion == null ? null : requestedVersion);
        const payload = parsed.payload;
        if (payload.key_version !== parsed.row.version || parsed.row.status !== "active") throw new ApiError("KEY_REVOKED", 401);
        const ipDigest = hashIp(masterSecret, getClientIp(request));
        let data;
        if (payload.op === "announcement") {
          data = transaction(db, () => {
            claimClientNonce(db, software.id, null, payload.nonce);
            const current = db.prepare("SELECT * FROM software_slots WHERE id=?").get(software.id);
            return announcementPublic(current, masterSecret);
          });
        } else if (payload.op === "login") {
          let license;
          let freeUser = null;
          const isFree = software.access_mode === "free";
          if (isFree) {
            const free = findOrCreateFreeUser(db, masterSecret, software, payload.machine_proof, ipDigest);
            license = free.license;
            freeUser = free.freeUser;
          } else {
            license = findLicenseByCode(db, software, masterSecret, payload.code);
          }
          const proofHashes = payload.machine_proof ? getMachineProofHashes(db, masterSecret, software, payload.machine_proof, parsed.rawKey) : [];
          const stableProofHash = payload.machine_proof ? stableMachineHash(masterSecret, software.id, payload.machine_proof) : null;
          if (isFree && !stableProofHash) throw new ApiError("MACHINE_PROOF_REQUIRED", 403);
          if (software.machine_check && !proofHashes.length) throw new ApiError("MACHINE_PROOF_REQUIRED", 403);
          data = transaction(db, () => {
            claimClientNonce(db, software.id, null, payload.nonce);
            const binding = db.prepare("SELECT * FROM license_bindings WHERE license_id=?").get(license.id);
            const proofHash = stableProofHash || proofHashes[0] || "unverified";
            if (!binding) {
              const deviceCount = Number(db.prepare("SELECT COUNT(*) AS count FROM license_bindings WHERE license_id=?").get(license.id).count);
              if (deviceCount >= Number(license.max_devices || 1)) throw new ApiError("DEVICE_LIMIT", 403);
              const now = nowIso();
              db.prepare("INSERT INTO license_bindings(license_id,machine_hash,ip_hash,machine_proof_version,first_bound_at,last_verified_at) VALUES(?,?,?,?,?,?)")
                .run(license.id, proofHash, ipDigest, stableProofHash ? "2" : "1", now, now);
            } else {
              if (software.machine_check && !proofHashes.includes(binding.machine_hash)) throw new ApiError("MACHINE_MISMATCH", 403);
              validateIpPolicy(software, binding, ipDigest, true);
              const now = nowIso();
              db.prepare("UPDATE license_bindings SET ip_hash=?,last_verified_at=? WHERE id=?").run(software.ip_change_policy === "update" ? ipDigest : binding.ip_hash, now, binding.id);
            }
            const token = randomToken(32);
            const sessionId = randomToken(18);
            const now = nowIso();
            const expires = new Date(Date.now() + Math.min(30 * 24 * 60 * 60 * 1000, Math.max(60, Number(software.session_ttl || 604800)) * 1000)).toISOString();
            db.prepare("INSERT INTO client_sessions(id,software_id,license_id,free_user_id,token_hash,machine_hash,ip_hash,key_version,created_at,last_heartbeat_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)")
              .run(sessionId, software.id, license.id, freeUser?.id || null, hashToken(masterSecret, token), proofHash, ipDigest, parsed.row.version, now, now, expires);
            db.prepare("UPDATE license_codes SET last_used_at=?,updated_at=? WHERE id=?").run(now, now, license.id);
            return { sessionToken: token, sessionId, serverTime: Date.now(), heartbeatInterval: Number(software.heartbeat_timeout || CLIENT_HEARTBEAT_TIMEOUT_SECONDS), expiresAt: expires, publicId: license.public_id, principalType: isFree ? "free" : "paid" };
          });
        } else {
          if (software.machine_check && (typeof payload.machine_proof !== "string" || !payload.machine_proof)) throw new ApiError("MACHINE_PROOF_REQUIRED", 403);
          const sessionMachineProofHashes = payload.machine_proof ? getMachineProofHashes(db, masterSecret, software, payload.machine_proof, parsed.rawKey) : [];
          payload.__machine_hash = sessionMachineProofHashes[0] || null;
          const loaded = loadSession(db, masterSecret, software, payload, ipDigest, sessionMachineProofHashes);
          const { session, binding } = loaded;
          data = transaction(db, () => {
            claimClientNonce(db, software.id, session.id, payload.nonce);
            if (software.machine_check && !sessionMachineProofHashes.includes(binding.machine_hash)) throw new ApiError("MACHINE_MISMATCH", 403);
            if (software.ip_check && software.ip_change_policy === "update" && binding.ip_hash !== ipDigest) {
              db.prepare("UPDATE license_bindings SET ip_hash=?,last_verified_at=? WHERE id=?").run(ipDigest, nowIso(), binding.id);
              db.prepare("UPDATE client_sessions SET ip_hash=? WHERE id=?").run(ipDigest, session.id);
              binding.ip_hash = ipDigest;
            }
            const now = nowIso();
            if (payload.op === "heartbeat") {
              db.prepare("UPDATE client_sessions SET last_heartbeat_at=?,ip_hash=? WHERE id=?").run(now, software.ip_change_policy === "update" ? ipDigest : session.ip_hash, session.id);
              db.prepare("UPDATE license_bindings SET last_verified_at=? WHERE id=?").run(now, binding.id);
              return { serverTime: Date.now(), heartbeatInterval: Number(software.heartbeat_timeout || CLIENT_HEARTBEAT_TIMEOUT_SECONDS), expiresAt: session.expires_at };
            }
            db.prepare("UPDATE client_sessions SET last_heartbeat_at=? WHERE id=?").run(now, session.id);
            if (payload.op === "pull_variables") {
              const since = Number.isSafeInteger(payload.since_version) ? payload.since_version : 0;
              const rows = db.prepare("SELECT * FROM software_variables WHERE software_id=? AND enabled=1 AND version>? ORDER BY var_key").all(software.id, since);
              const variables = rows.map((row) => ({ key: row.var_key, value: decryptAtRest(masterSecret, row.value_encrypted), version: row.version, updatedAt: row.updated_at }));
              return { variables, latestVersion: rows.reduce((max, row) => Math.max(max, row.version), since) };
            }
            if (payload.op === "report") {
              const slot = findDataSlot(db, software, payload.data_slot || "legacy");
              const mode = payload.mode == null ? "overwrite" : payload.mode;
              return writeDataStore(db, masterSecret, software, session.license_id, slot, payload.data, mode, true, { recordHistory: true, sessionId: session.id, machineHash: payload.__machine_hash, freeUserId: loaded.freeUser?.id || null });
            }
            if (payload.op === "ingest") {
              const header = payload.header;
              const content = payload.content;
              if (!header || typeof header !== "object" || Array.isArray(header) || header.dataSlot == null) throw new ApiError("INVALID_INGEST_HEADER");
              const headerJson = JSON.stringify(header);
              if (Buffer.byteLength(headerJson, "utf8") > 16 * 1024) throw new ApiError("INGEST_HEADER_TOO_LARGE", 413);
              const mode = header.mode === "event" ? "event" : header.mode === "snapshot" ? "snapshot" : null;
              if (!mode || !["application/json", "text/plain"].includes(String(header.contentType || "application/json"))) throw new ApiError("INVALID_INGEST_HEADER");
              if (header.eventId != null && (typeof header.eventId !== "string" || header.eventId.length < 1 || header.eventId.length > 128)) throw new ApiError("INVALID_EVENT_ID");
              const slot = findDataSlot(db, software, String(header.dataSlot));
              const serialized = typeof content === "string" ? content : JSON.stringify(content ?? null);
              const size = Buffer.byteLength(serialized, "utf8");
              const receiveSettings = getSetting(db, "receive_settings", { enabled: true, maxPayloadBytes: MAX_REPORT_BYTES });
              if (!receiveSettings.enabled) throw new ApiError("RECEIVING_DISABLED", 403);
              if (size > Math.min(MAX_REPORT_BYTES, Number(receiveSettings.maxPayloadBytes) || MAX_REPORT_BYTES)) throw new ApiError("PAYLOAD_TOO_LARGE", 413);
              const digest = sha256(serialized);
              if (header.size != null && Number(header.size) !== size) throw new ApiError("INGEST_SIZE_MISMATCH");
              if (header.sha256 != null && String(header.sha256).toLowerCase() !== digest) throw new ApiError("INGEST_DIGEST_MISMATCH");
              const eventId = header.eventId || null;
              if (eventId) {
                const prior = db.prepare("SELECT id,size,sha256,status FROM ingest_events WHERE software_id=? AND slot_id=? AND license_id=? AND event_id=?").get(software.id, slot.id, session.license_id, eventId);
                if (prior) return { id: prior.id, accepted: prior.status === "received", duplicate: true, size: prior.size, sha256: prior.sha256, eventId };
              }
              const now = nowIso();
              const encrypted = encryptAtRest(masterSecret, content);
              const inserted = db.prepare(`INSERT INTO ingest_events(software_id,slot_id,license_id,free_user_id,session_id,event_id,mode,content_type,schema_version,header_json,content_encrypted,size,sha256,occurred_at,received_at,status)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'received')`).run(software.id, slot.id, session.license_id, loaded.freeUser?.id || null, session.id, eventId, mode, String(header.contentType || "application/json"), Number.isSafeInteger(header.schemaVersion) ? header.schemaVersion : 1, headerJson, encrypted, size, digest, header.occurredAt || null, now);
              return { id: Number(inserted.lastInsertRowid), accepted: true, duplicate: false, eventId, mode, size, sha256: digest, receivedAt: now };
            }
            if (payload.op === "manifest") {
              const resources = db.prepare("SELECT id,original_name,sha256,size,mime,created_at FROM software_resources WHERE software_id=? AND status='ready' ORDER BY id").all(software.id);
              return { resources: resources.map((row) => ({ id: row.id, originalName: row.original_name, sha256: row.sha256, size: row.size, mime: row.mime, createdAt: row.created_at })) };
            }
            if (payload.op === "file_chunk") {
              const file = db.prepare("SELECT * FROM software_resources WHERE id=? AND software_id=? AND status='ready'").get(Number(payload.file_id), software.id);
              if (!file) throw new ApiError("FILE_NOT_FOUND", 404);
              const path = safeResourcePath(file);
              const offset = payload.offset == null ? 0 : Number(payload.offset);
              const requestedLength = payload.length == null ? MAX_FILE_CHUNK_BYTES : Number(payload.length);
              const length = Math.min(MAX_FILE_CHUNK_BYTES, requestedLength);
              if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(length) || length < 1 || offset >= file.size) throw new ApiError("INVALID_OFFSET");
              const count = Math.min(length, file.size - offset);
              const fd = openSync(path, "r");
              const chunk = Buffer.alloc(count);
              try { readSync(fd, chunk, 0, count, offset); } finally { closeSync(fd); }
              return { fileId: file.id, offset, length: count, totalSize: file.size, sha256: file.sha256, chunk: chunk.toString("base64"), eof: offset + count >= file.size };
            }
            throw new ApiError("INVALID_OPERATION");
          });
        }
        response = encryptedSuccess(responseKey.rawKey, software.slug, responseKey.row.version, data);
      }
    } catch (error) {
      const apiError = error instanceof ApiError ? error : new ApiError("INVALID_REQUEST");
      if (!responseKey) {
        try { responseKey = getActiveSoftwareKey(db, masterSecret, software.id); } catch { return reply.code(200).header("content-type", "application/octet-stream").send(Buffer.alloc(0)); }
      }
      response = encryptedFailure(responseKey.rawKey, software.slug, responseKey.row.version, apiError.code, apiError.status);
    }
    return reply.code(200).header("content-type", "application/octet-stream").header("cache-control", "no-store").header("x-content-type-options", "nosniff").send(response);
  });

  // v1 remains available as an explicitly scoped legacy compatibility window.
  app.post("/api/v1/client", async (request, reply) => {
    const rate = app.clientRateLimit(request);
    let response;
    try {
      if (!rate.allowed) return reply.code(200).header("content-type", "application/octet-stream").send(await encryptClientResponse(masterSecret, { ok: false, status: 429, error: "RATE_LIMITED", timestamp: Date.now() }));
      if (String(request.headers["content-type"] || "").toLowerCase().split(";")[0] !== "application/octet-stream") throw new ApiError("INVALID_REQUEST");
      const body = Buffer.isBuffer(request.body) ? request.body : Buffer.from(request.body || "");
      if (!body.length || body.length > MAX_CLIENT_PACKET_BYTES) throw new ApiError("INVALID_REQUEST");
      const payload = await decryptClientPacket(masterSecret, body);
      if (!payload || !Number.isSafeInteger(payload.timestamp) || Math.abs(Date.now() - payload.timestamp) > 120000 || typeof payload.nonce !== "string" || !NONCE_PATTERN.test(payload.nonce) || !["verify", "pull_variables", "report"].includes(payload.op)) throw new ApiError("INVALID_REQUEST");
      const license = db.prepare("SELECT * FROM license_keys WHERE code_encrypted=? LIMIT 1").get(clientCodeHash(masterSecret, payload.code));
      if (!license || license.status !== "active") throw new ApiError("INVALID_CREDENTIALS", 401);
      if (license.expires_at && new Date(license.expires_at).getTime() <= Date.now()) throw new ApiError("LICENSE_EXPIRED", 401);
      transaction(db, () => {
        pruneNonces(db);
        const result = db.prepare("INSERT OR IGNORE INTO nonce_cache(nonce,license_id,expires_at) VALUES(?,?,?)").run(payload.nonce, license.id, new Date(Date.now() + 5 * 60 * 1000).toISOString());
        if (Number(result.changes) !== 1) throw new ApiError("REPLAY_DETECTED", 409);
      });
      if (typeof payload.device_id !== "string" || payload.device_id.length < 1 || payload.device_id.length > 128) throw new ApiError("INVALID_DEVICE");
      if (payload.op === "verify") {
        const existing = db.prepare("SELECT id FROM license_devices WHERE license_id=? AND device_id=?").get(license.id, payload.device_id);
        if (!existing) {
          const count = db.prepare("SELECT COUNT(*) AS count FROM license_devices WHERE license_id=?").get(license.id).count;
          if (Number(count) >= license.max_devices) throw new ApiError("DEVICE_LIMIT", 403);
          db.prepare("INSERT INTO license_devices(license_id,device_id,first_seen_at,last_seen_at) VALUES(?,?,?,?)").run(license.id, payload.device_id, nowIso(), nowIso());
        } else db.prepare("UPDATE license_devices SET last_seen_at=? WHERE id=?").run(nowIso(), existing.id);
        response = { publicId: license.public_id, expiresAt: license.expires_at, deviceCount: db.prepare("SELECT COUNT(*) AS count FROM license_devices WHERE license_id=?").get(license.id).count, maxDevices: license.max_devices };
      } else if (payload.op === "pull_variables") {
        if (!db.prepare("SELECT id FROM license_devices WHERE license_id=? AND device_id=?").get(license.id, payload.device_id)) throw new ApiError("DEVICE_NOT_VERIFIED", 403);
        const since = Number.isInteger(payload.since_version) ? payload.since_version : 0;
        const rows = db.prepare("SELECT * FROM variables WHERE enabled=1 AND version>? ORDER BY var_key").all(since);
        response = { variables: rows.map((row) => ({ key: row.var_key, value: decryptAtRest(masterSecret, row.value_encrypted), version: row.version, updatedAt: row.updated_at })), receiveSettings: getSetting(db, "receive_settings", { enabled: true, maxPayloadBytes: MAX_REPORT_BYTES }), latestVersion: rows.reduce((max, row) => Math.max(max, row.version), since) };
      } else {
        const settings = getSetting(db, "receive_settings", { enabled: true, maxPayloadBytes: MAX_REPORT_BYTES });
        if (!settings.enabled || jsonBodySize(payload.data) > Math.min(MAX_REPORT_BYTES, Number(settings.maxPayloadBytes) || MAX_REPORT_BYTES)) throw new ApiError("PAYLOAD_TOO_LARGE", 413);
        if (!db.prepare("SELECT id FROM license_devices WHERE license_id=? AND device_id=?").get(license.id, payload.device_id)) throw new ApiError("DEVICE_NOT_VERIFIED", 403);
        const size = jsonBodySize(payload.data);
        db.prepare("INSERT INTO reports(license_id,device_id,payload_encrypted,payload_size,ip_hash,received_at) VALUES(?,?,?,?,?,?)").run(license.id, payload.device_id, encryptAtRest(masterSecret, payload.data), size, hashIp(masterSecret, getClientIp(request)), nowIso());
        response = { accepted: true, receivedAt: nowIso(), size };
      }
      response = await encryptClientResponse(masterSecret, { ok: true, status: 200, data: response, timestamp: Date.now() });
    } catch (error) {
      const apiError = error instanceof ApiError ? error : new ApiError("INVALID_REQUEST");
      response = await encryptClientResponse(masterSecret, { ok: false, status: apiError.status, error: apiError.code, timestamp: Date.now() });
    }
    return reply.code(200).header("content-type", "application/octet-stream").header("cache-control", "no-store").send(response);
  });

  async function requireAdmin(request, reply) {
    if (!checkOrigin(request)) return reply.code(403).send({ error: "ORIGIN_FORBIDDEN" });
    const token = request.cookies[SESSION_COOKIE];
    if (!token) return reply.code(401).send({ error: "UNAUTHENTICATED" });
    const row = db.prepare(`SELECT s.*,u.username,u.role,u.active,u.must_change_password FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked_at IS NULL`).get(hashToken(masterSecret, token));
    if (!row || !row.active || new Date(row.expires_at).getTime() <= Date.now()) { clearAuthCookies(reply); return reply.code(401).send({ error: "UNAUTHENTICATED" }); }
    request.auth = { sessionId: row.id, userId: row.user_id, username: row.username, role: row.role, csrfHash: row.csrf_hash, mustChangePassword: Boolean(row.must_change_password) };
    if (request.auth.mustChangePassword && !["/api/admin/me", "/api/admin/password"].includes(request.url.split("?")[0])) return reply.code(428).send({ error: "PASSWORD_CHANGE_REQUIRED" });
    db.prepare("UPDATE sessions SET last_seen_at=? WHERE id=?").run(nowIso(), row.id);
  }

  function requireRole(role) {
    const ranks = { viewer: 1, operator: 2, owner: 3 };
    return async (request, reply) => {
      const result = await requireAdmin(request, reply);
      if (result) return result;
      if ((ranks[request.auth.role] || 0) < (ranks[role] || 0)) return reply.code(403).send({ error: "FORBIDDEN" });
    };
  }

  async function requireMutation(request, reply) {
    const result = await requireAdmin(request, reply);
    if (result) return result;
    const csrf = request.headers["x-csrf-token"];
    const cookieCsrf = request.cookies[CSRF_COOKIE];
    if (!csrf || !cookieCsrf || csrf !== cookieCsrf || hashToken(masterSecret, csrf) !== request.auth.csrfHash) return reply.code(403).send({ error: "CSRF_INVALID" });
  }

  const requireOperatorMutation = async (request, reply) => {
    const result = await requireMutation(request, reply);
    if (result) return result;
    if (!["owner", "operator"].includes(request.auth.role)) return reply.code(403).send({ error: "FORBIDDEN" });
  };
  const requireOwnerMutation = async (request, reply) => {
    const result = await requireMutation(request, reply);
    if (result) return result;
    if (request.auth.role !== "owner") return reply.code(403).send({ error: "FORBIDDEN" });
  };

  app.post("/api/admin/login", async (request, reply) => {
    if (!checkOrigin(request)) return reply.code(403).send({ error: "ORIGIN_FORBIDDEN" });
    const ip = getClientIp(request); const windowStart = Math.floor(Date.now() / 60000) * 60000;
    for (const [key, bucket] of app.loginBuckets) if (bucket.windowStart !== windowStart) app.loginBuckets.delete(key);
    const limit = Math.max(1, Math.min(100, Number(getSetting(db, "login_rate_limit_per_minute", 10)) || 10));
    const current = app.loginBuckets.get(`login:${ip}`); const bucket = current && current.windowStart === windowStart ? current : { windowStart, count: 0 }; bucket.count += 1; app.loginBuckets.set(`login:${ip}`, bucket);
    if (bucket.count > limit) return reply.code(429).header("retry-after", "60").send({ error: "RATE_LIMITED" });
    const username = request.body?.username; const password = request.body?.password;
    if (typeof username !== "string" || typeof password !== "string" || username.length > 128 || password.length > 256) return reply.code(401).send({ error: "INVALID_CREDENTIALS" });
    const user = db.prepare("SELECT * FROM users WHERE username=? AND active=1").get(username);
    if (!user || !(await argon2.verify(user.password_hash, password))) return reply.code(401).send({ error: "INVALID_CREDENTIALS" });
    const sessionToken = randomToken(32); const csrfToken = randomToken(32); const now = nowIso();
    db.prepare("INSERT INTO sessions(id,user_id,token_hash,csrf_hash,expires_at,created_at,last_seen_at,ip_hash) VALUES(?,?,?,?,?,?,?,?)").run(randomToken(18), user.id, hashToken(masterSecret, sessionToken), hashToken(masterSecret, csrfToken), new Date(Date.now() + SESSION_TTL_MS).toISOString(), now, now, hashIp(masterSecret, ip));
    setSecureCookies(reply, sessionToken, csrfToken);
    audit(db, { userId: user.id, action: "login", objectType: "session", ipHash: hashIp(masterSecret, ip) });
    return { user: publicUser(user), csrfToken };
  });

  app.post("/api/admin/logout", { preHandler: requireMutation }, async (request, reply) => { db.prepare("UPDATE sessions SET revoked_at=? WHERE id=?").run(nowIso(), request.auth.sessionId); clearAuthCookies(reply); audit(db, { userId: request.auth.userId, action: "logout", objectType: "session", ipHash: hashIp(masterSecret, getClientIp(request)) }); return { ok: true }; });
  app.get("/api/admin/me", { preHandler: requireAdmin }, async (request) => { const user = db.prepare("SELECT * FROM users WHERE id=?").get(request.auth.userId); return { user: publicUser(user), csrfToken: request.cookies[CSRF_COOKIE] || null }; });
  app.post("/api/admin/password", { preHandler: requireMutation }, async (request, reply) => {
    const password = request.body?.password;
    if (typeof password !== "string" || password.length < 14 || password.length > 256) return reply.code(400).send({ error: "PASSWORD_TOO_WEAK" });
    const passwordHash = await argon2.hash(password, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
    const now = nowIso();
    db.prepare("UPDATE users SET password_hash=?,must_change_password=0,updated_at=? WHERE id=?").run(passwordHash, now, request.auth.userId);
    db.prepare("UPDATE sessions SET revoked_at=? WHERE user_id=? AND id<>? AND revoked_at IS NULL").run(now, request.auth.userId, request.auth.sessionId);
    audit(db, { userId: request.auth.userId, action: "change_password", objectType: "user", objectId: request.auth.userId, ipHash: hashIp(masterSecret, getClientIp(request)), metadata: { otherSessionsRevoked: true } });
    return { ok: true };
  });

  // Software slots and key lifecycle.
  app.get("/api/admin/software", { preHandler: requireAdmin }, async (request) => {
    const page = Math.max(1, Number(request.query?.page) || 1);
    const limit = safeLimit(request.query?.limit, 100, 500);
    const offset = (page - 1) * limit;
    const total = db.prepare("SELECT COUNT(*) AS count FROM software_slots").get().count;
    const items = db.prepare("SELECT * FROM software_slots ORDER BY id LIMIT ? OFFSET ?").all(limit, offset).map((row) => softwarePublic(db, row));
    return { items, page, limit, total };
  });
  app.delete("/api/admin/software/:software_slot", { preHandler: requireOwnerMutation }, async (request, reply) => {
    const software = findSoftware(db, request.params.software_slot);
    const releaseDirs = db.prepare("SELECT id FROM software_releases WHERE software_id=?").all(software.id).map((row) => join(FILES_ROOT, String(row.id)));
    transaction(db, () => { db.prepare("DELETE FROM software_slots WHERE id=?").run(software.id); });
    const resourceDir = join(FILES_ROOT, "resources", String(software.id));
    for (const dir of [...releaseDirs, resourceDir]) { try { rmSync(dir, { recursive: true, force: true }); } catch {} }
    audit(db, { userId: request.auth.userId, action: "delete", objectType: "software", objectId: software.id, softwareId: software.id, metadata: { slug: software.slug } });
    return { ok: true };
  });
  app.post("/api/admin/software", { preHandler: requireOwnerMutation }, async (request, reply) => {
    const body = request.body || {}; const slug = String(body.slug || "").toLowerCase(); const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!SLUG_PATTERN.test(slug) || !name || name.length > 128) return reply.code(400).send({ error: "INVALID_SOFTWARE" });
    const now = nowIso(); let row;
    try {
      const accessMode = body.isFree === true || body.free === true || body.accessMode === "free" ? "free" : "paid";
      const result = db.prepare(`INSERT INTO software_slots(slug,name,description,status,machine_check,ip_check,ip_change_policy,heartbeat_timeout,session_ttl,access_mode,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).run(slug, name, String(body.description || "").slice(0, 1000), body.status === "disabled" ? "disabled" : "active", accessMode === "free" ? 1 : (body.machineCheck === false ? 0 : 1), body.ipCheck === true ? 1 : 0, ["deny", "update", "allow"].includes(body.ipChangePolicy) ? body.ipChangePolicy : "deny", Math.min(3600, Math.max(30, Number(body.heartbeatTimeout) || 300)), Math.min(2592000, Math.max(60, Number(body.sessionTtl) || 604800)), accessMode, now, now);
      row = db.prepare("SELECT * FROM software_slots WHERE id=?").get(result.lastInsertRowid);
      ensureSoftwareKey(db, masterSecret, row.id);
      db.prepare("INSERT INTO data_slots(software_id,slug,name,description,enabled,single_limit,rolling_24h_limit,permanent_limit,max_records,retention_days,created_at,updated_at) VALUES(?,?,?,?,?,0,0,0,0,90,?,?)").run(row.id, "legacy", "默认数据槽", "自动创建的默认数据槽", 1, now, now);
    } catch { return reply.code(409).send({ error: "SOFTWARE_EXISTS" }); }
    audit(db, { userId: request.auth.userId, action: "create", objectType: "software", objectId: row.id, softwareId: row.id, metadata: { slug } }); return { software: softwarePublic(db, row) };
  });
  app.get("/api/admin/software/:software_slot", { preHandler: requireAdmin }, async (request, reply) => { try { return { software: softwarePublic(db, findSoftware(db, request.params.software_slot)) }; } catch (error) { if (error instanceof ApiError) return reply.code(error.status).send({ error: error.code }); throw error; } });
  app.patch("/api/admin/software/:software_slot", { preHandler: requireOwnerMutation }, async (request, reply) => { const current = findSoftware(db, request.params.software_slot); const body = request.body || {}; const next = { name: typeof body.name === "string" && body.name.trim() ? body.name.trim().slice(0, 128) : current.name, description: typeof body.description === "string" ? body.description.slice(0, 1000) : current.description, status: body.status === "disabled" ? "disabled" : body.status === "active" ? "active" : current.status, machineCheck: Object.hasOwn(body, "machineCheck") ? (body.machineCheck ? 1 : 0) : current.machine_check, ipCheck: Object.hasOwn(body, "ipCheck") ? (body.ipCheck ? 1 : 0) : current.ip_check, ipChangePolicy: ["deny", "update", "allow"].includes(body.ipChangePolicy) ? body.ipChangePolicy : current.ip_change_policy, heartbeatTimeout: Object.hasOwn(body, "heartbeatTimeout") ? Math.min(3600, Math.max(30, Number(body.heartbeatTimeout) || 300)) : current.heartbeat_timeout, sessionTtl: Object.hasOwn(body, "sessionTtl") ? Math.min(2592000, Math.max(60, Number(body.sessionTtl) || 604800)) : current.session_ttl }; db.prepare("UPDATE software_slots SET name=?,description=?,status=?,machine_check=?,ip_check=?,ip_change_policy=?,heartbeat_timeout=?,session_ttl=?,updated_at=? WHERE id=?").run(next.name, next.description, next.status, next.machineCheck, next.ipCheck, next.ipChangePolicy, next.heartbeatTimeout, next.sessionTtl, nowIso(), current.id); const row = findSoftware(db, current.slug); audit(db, { userId: request.auth.userId, action: "update", objectType: "software", objectId: row.id, softwareId: row.id }); return { software: softwarePublic(db, row) }; });
  app.get("/api/admin/software/:software_slot/keys", { preHandler: requireAdmin }, async (request) => { const software = findSoftware(db, request.params.software_slot); return { items: db.prepare("SELECT * FROM software_keys WHERE software_id=? ORDER BY version DESC").all(software.id).map(keyPublic) }; });
  app.post("/api/admin/software/:software_slot/keys/rotate", { preHandler: requireOwnerMutation }, async (request) => {
    const software = findSoftware(db, request.params.software_slot);
    const result = transaction(db, () => {
      const current = db.prepare("SELECT COALESCE(MAX(version),0) AS version FROM software_keys WHERE software_id=?").get(software.id);
      const version = Number(current.version) + 1;
      const raw = generateSoftwareKey();
      const now = nowIso();
      db.prepare("UPDATE software_keys SET status='revoked',revoked_at=? WHERE software_id=? AND status='active'").run(now, software.id);
      db.prepare("INSERT INTO software_keys(software_id,version,encrypted_key,fingerprint,status,not_before,created_at) VALUES(?,?,?,?,?,?,?)").run(software.id, version, encryptAtRest(masterSecret, raw.toString("base64url")), softwareKeyFingerprint(raw), "active", now, now);
      db.prepare("UPDATE client_sessions SET revoked_at=?,revoke_reason=? WHERE software_id=? AND revoked_at IS NULL").run(now, "software_key_rotated", software.id);
      return { version, row: db.prepare("SELECT * FROM software_keys WHERE software_id=? AND version=?").get(software.id, version) };
    });
    audit(db, { userId: request.auth.userId, action: "rotate", objectType: "software_key", objectId: result.version, softwareId: software.id, metadata: { sessionsRevoked: true } });
    return { key: keyPublic(result.row), exportRequired: true };
  });
  app.post("/api/admin/software/:software_slot/keys/:version/revoke", { preHandler: requireOwnerMutation }, async (request, reply) => { const software = findSoftware(db, request.params.software_slot); const result = db.prepare("UPDATE software_keys SET status='revoked',revoked_at=? WHERE software_id=? AND version=? AND status='active'").run(nowIso(), software.id, Number(request.params.version)); if (!result.changes) return reply.code(404).send({ error: "NOT_FOUND" }); db.prepare("UPDATE client_sessions SET revoked_at=? WHERE software_id=?").run(nowIso(), software.id); audit(db, { userId: request.auth.userId, action: "revoke", objectType: "software_key", objectId: request.params.version, softwareId: software.id }); return { ok: true }; });
  function softwareKeyExport(request, reply) {
    const software = findSoftware(db, request.params.software_slot);
    const requestedVersion = request.params.version ?? request.query?.version;
    const parsedVersion = Number(requestedVersion);
    const row = db.prepare("SELECT * FROM software_keys WHERE software_id=? AND version=? AND status='active' AND exported_at IS NULL").get(software.id, Number.isSafeInteger(parsedVersion) ? parsedVersion : -1);
    if (!row || !keyWithinWindow(row)) return reply.code(404).send({ error: "NOT_FOUND" });
    let raw;
    try {
      const claimed = transaction(db, () => {
        const result = db.prepare("UPDATE software_keys SET exported_at=? WHERE id=? AND exported_at IS NULL AND status='active'").run(nowIso(), row.id);
        if (Number(result.changes) !== 1) throw new ApiError("KEY_ALREADY_EXPORTED", 409);
        return db.prepare("SELECT * FROM software_keys WHERE id=?").get(row.id);
      });
      raw = decodeStoredSoftwareKey(masterSecret, claimed.encrypted_key);
    } catch (error) {
      if (error instanceof ApiError) return reply.code(error.status).send({ error: error.code });
      return reply.code(503).send({ error: "KEY_UNAVAILABLE" });
    }
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const exportedAt = nowIso();
    audit(db, { userId: request.auth.userId, action: "export", objectType: "software_key", objectId: row.version, softwareId: software.id, metadata: { sensitive: true } });
    return { softwareSlot: software.slug, keyVersion: row.version, key: raw.toString("base64url"), expiresAt };
  }
  app.post("/api/admin/software/:software_slot/keys/:version/export", { preHandler: requireOwnerMutation }, softwareKeyExport);

  // Public announcements contain no credentials and are also available through
  // the encrypted v2 announcement operation.
  app.get("/api/public/software/:software_slot/announcement", async (request, reply) => {
    try {
      const software = findSoftware(db, request.params.software_slot);
      if (software.status !== "active") return reply.code(404).send({ error: "NOT_FOUND" });
      return announcementPublic(software, masterSecret);
    } catch (error) {
      if (error instanceof ApiError) return reply.code(error.status).send({ error: error.code === "INVALID_SOFTWARE" ? "NOT_FOUND" : error.code });
      throw error;
    }
  });

  function listScopedLicenses(software, query, role = "viewer") {
    const page = Math.max(1, Number(query?.page) || 1); const limit = safeLimit(query?.limit, 50, 500); const status = ["active", "revoked"].includes(query?.status) ? query.status : null; const search = typeof query?.search === "string" ? query.search.trim().toLowerCase().slice(0, 128) : "";
    const baseParams = [software.id]; const baseWhere = status ? " AND l.status=?" : ""; if (status) baseParams.push(status);
    if (!search) {
      const total = db.prepare(`SELECT COUNT(*) AS count FROM license_codes l WHERE l.software_id=?${baseWhere}`).get(...baseParams).count;
      const rows = db.prepare(`SELECT l.*,b.machine_hash AS bound_machine_hash,b.first_bound_at AS bound_at FROM license_codes l LEFT JOIN license_bindings b ON b.license_id=l.id WHERE l.software_id=?${baseWhere} ORDER BY l.id DESC LIMIT ? OFFSET ?`).all(...baseParams, limit, (page - 1) * limit);
      return { items: rows.map((row) => licenseRowPublic(row, role)), page, limit, total };
    }
    const allRows = db.prepare(`SELECT l.*,b.machine_hash AS bound_machine_hash,b.first_bound_at AS bound_at FROM license_codes l LEFT JOIN license_bindings b ON b.license_id=l.id WHERE l.software_id=?${baseWhere} ORDER BY l.id DESC`).all(...baseParams);
    const filtered = allRows.map((row) => ({ row, item: licenseRowPublic(row, role) })).filter(({ row, item }) => {
      const searchable = [row.public_id, row.note, row.bound_machine_hash].filter(Boolean).join(" ").toLowerCase();
      return searchable.includes(search) || (role === "owner" && String(item.code || "").toLowerCase().includes(search));
    }).map(({ item }) => item);
    return { items: filtered.slice((page - 1) * limit, page * limit), page, limit, total: filtered.length };
  }
  function licenseRowPublic(row, role = "viewer") {
    const canReveal = role === "owner";
    let code = null;
    if (canReveal && row.code_encrypted) { try { code = decryptAtRest(masterSecret, row.code_encrypted); } catch { code = null; } }
    return { ...licensePublic(row, row.bound_machine_hash ? 1 : 0), code, machineHash: canReveal ? (row.bound_machine_hash || null) : (row.bound_machine_hash ? truncateHash(row.bound_machine_hash) : null), boundAt: row.bound_at || null };
  }
  function truncateHash(value) { return typeof value === "string" ? `${value.slice(0, 8)}…` : null; }
  app.get("/api/admin/software/:software_slot/licenses", { preHandler: requireAdmin }, async (request) => listScopedLicenses(findSoftware(db, request.params.software_slot), request.query || {}, request.auth.role));
  app.post("/api/admin/software/:software_slot/licenses", { preHandler: requireOperatorMutation }, async (request) => {
    const software = findSoftware(db, request.params.software_slot);
    const body = request.body || {};
    const expiresAt = validIso(body.expiresAt); const maxDevices = Math.min(100, Math.max(1, Number(body.maxDevices) || 1)); const note = typeof body.note === "string" ? body.note.slice(0, 500) : "";
    const codes = []; const duplicates = [];
    const insertLicense = (code) => db.prepare("INSERT OR IGNORE INTO license_codes(software_id,code_hash,code_encrypted,public_id,status,expires_at,max_devices,note,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)").run(software.id, clientCodeHash(masterSecret, code), encryptAtRest(masterSecret, code), randomToken(12), "active", expiresAt, maxDevices, note, nowIso(), nowIso());
    transaction(db, () => {
      if (Array.isArray(body.codes)) {
        const wanted = body.codes.filter((code) => typeof code === "string").map((code) => code.trim()).filter(Boolean).slice(0, 1000);
        for (const code of wanted) {
          if (!CODE_PATTERN.test(code)) throw new ApiError("INVALID_LICENSE_CODE", 400);
          const result = insertLicense(code);
          if (Number(result.changes) === 1) codes.push(code); else duplicates.push(code);
        }
      } else {
        const count = Math.min(1000, Math.max(1, Number(body.count) || 1));
        const prefix = normalizeLicensePrefix(body.prefix);
        for (let i = 0; i < count; i += 1) {
          let code; let inserted = false;
          for (let attempt = 0; attempt < 20 && !inserted; attempt += 1) { code = generatedLicenseCode(prefix); const result = insertLicense(code); inserted = Number(result.changes) === 1; }
          if (!inserted) throw new ApiError("GENERATION_FAILED", 500);
          codes.push(code);
        }
      }
    });
    audit(db, { userId: request.auth.userId, action: "create", objectType: "license", softwareId: software.id, metadata: { count: codes.length, manual: Array.isArray(body.codes) } });
    return { codes, count: codes.length, duplicates };
  });
  app.post("/api/admin/software/:software_slot/licenses/batch", { preHandler: requireOperatorMutation }, async (request, reply) => {
    const software = findSoftware(db, request.params.software_slot);
    const body = request.body || {};
    const action = String(body.action || "");
    if (!["ban", "activate", "reset-binding", "delete"].includes(action)) return reply.code(400).send({ error: "INVALID_ACTION" });
    const ids = Array.isArray(body.ids) ? body.ids.map(Number).filter((id) => Number.isSafeInteger(id) && id > 0).slice(0, 1000) : [];
    if (!ids.length) return reply.code(400).send({ error: "INVALID_IDS" });
    let changed = 0;
    transaction(db, () => {
      for (const id of ids) {
        let result;
        if (action === "ban") {
          result = db.prepare("UPDATE license_codes SET status='revoked',updated_at=? WHERE id=? AND software_id=?").run(nowIso(), id, software.id);
          revokeLicenseSessions(db, id, "license_revoked");
        } else if (action === "activate") result = db.prepare("UPDATE license_codes SET status='active',updated_at=? WHERE id=? AND software_id=?").run(nowIso(), id, software.id);
        else if (action === "reset-binding") {
          result = db.prepare("DELETE FROM license_bindings WHERE license_id=? AND license_id IN (SELECT id FROM license_codes WHERE software_id=?)").run(id, software.id);
          revokeLicenseSessions(db, id, "binding_reset");
        } else {
          revokeLicenseSessions(db, id, "license_deleted");
          result = db.prepare("DELETE FROM license_codes WHERE id=? AND software_id=?").run(id, software.id);
        }
        changed += Number(result.changes);
      }
    });
    audit(db, { userId: request.auth.userId, action: `batch_${action}`, objectType: "license", softwareId: software.id, metadata: { count: changed } });
    return { ok: true, changed };
  });
  app.patch("/api/admin/software/:software_slot/licenses/:id", { preHandler: requireOperatorMutation }, async (request, reply) => {
    const software = findSoftware(db, request.params.software_slot); const id = Number(request.params.id);
    const row = db.prepare("SELECT * FROM license_codes WHERE id=? AND software_id=?").get(id, software.id);
    if (!row) return reply.code(404).send({ error: "NOT_FOUND" });
    const body = request.body || {}; const nextStatus = body.status === "revoked" ? "revoked" : body.status === "active" ? "active" : row.status;
    const expires = Object.hasOwn(body, "expiresAt") ? validIso(body.expiresAt) : row.expires_at;
    const max = Object.hasOwn(body, "maxDevices") ? Math.min(100, Math.max(1, Number(body.maxDevices) || 1)) : row.max_devices;
    const note = typeof body.note === "string" ? body.note.slice(0, 500) : row.note;
    db.prepare("UPDATE license_codes SET status=?,expires_at=?,max_devices=?,note=?,updated_at=? WHERE id=?").run(nextStatus, expires, max, note, nowIso(), id);
    if (nextStatus === "revoked" || (expires && (!row.expires_at || expires !== row.expires_at) && new Date(expires).getTime() <= Date.now())) revokeLicenseSessions(db, id, "license_updated");
    audit(db, { userId: request.auth.userId, action: "update", objectType: "license", objectId: id, softwareId: software.id, metadata: { status: nextStatus } });
    return { license: licensePublic(db.prepare("SELECT * FROM license_codes WHERE id=?").get(id), db.prepare("SELECT COUNT(*) AS count FROM license_bindings WHERE license_id=?").get(id).count) };
  });
  app.delete("/api/admin/software/:software_slot/licenses/:id", { preHandler: requireOperatorMutation }, async (request, reply) => {
    const software = findSoftware(db, request.params.software_slot); const id = Number(request.params.id);
    const result = transaction(db, () => { revokeLicenseSessions(db, id, "license_deleted"); return db.prepare("DELETE FROM license_codes WHERE id=? AND software_id=?").run(id, software.id); });
    if (!result.changes) return reply.code(404).send({ error: "NOT_FOUND" });
    audit(db, { userId: request.auth.userId, action: "delete", objectType: "license", objectId: id, softwareId: software.id }); return { ok: true };
  });
  app.post("/api/admin/software/:software_slot/licenses/:id/reset-binding", { preHandler: requireOwnerMutation }, async (request, reply) => { const software = findSoftware(db, request.params.software_slot); const result = db.prepare("DELETE FROM license_bindings WHERE license_id=? AND license_id IN (SELECT id FROM license_codes WHERE software_id=?)").run(Number(request.params.id), software.id); if (!result.changes) return reply.code(404).send({ error: "NOT_FOUND" }); db.prepare("UPDATE client_sessions SET revoked_at=? WHERE license_id=?").run(nowIso(), Number(request.params.id)); audit(db, { userId: request.auth.userId, action: "reset_binding", objectType: "license_binding", objectId: request.params.id, softwareId: software.id }); return { ok: true }; });
  app.get("/api/admin/software/:software_slot/bindings", { preHandler: requireAdmin }, async (request) => { const software = findSoftware(db, request.params.software_slot); return { items: db.prepare("SELECT b.*,l.public_id FROM license_bindings b JOIN license_codes l ON l.id=b.license_id WHERE l.software_id=? ORDER BY b.id DESC").all(software.id).map((row) => ({ id: row.id, licenseId: row.license_id, publicId: row.public_id, machineHash: row.machine_hash, ipHash: row.ip_hash, firstBoundAt: row.first_bound_at, lastVerifiedAt: row.last_verified_at, resetAt: row.reset_at })) }; });
  app.get("/api/admin/software/:software_slot/sessions", { preHandler: requireAdmin }, async (request) => { const software = findSoftware(db, request.params.software_slot); return { items: db.prepare("SELECT s.*,l.public_id FROM client_sessions s JOIN license_codes l ON l.id=s.license_id WHERE s.software_id=? ORDER BY s.created_at DESC LIMIT ?").all(software.id, safeLimit(request.query?.limit, 100, 500)).map((row) => ({ id: row.id, licenseId: row.license_id, publicId: row.public_id, machineHash: row.machine_hash, createdAt: row.created_at, lastHeartbeatAt: row.last_heartbeat_at, expiresAt: row.expires_at, revokedAt: row.revoked_at, active: !row.revoked_at && new Date(row.expires_at).getTime() > Date.now() })) }; });
  app.post("/api/admin/software/:software_slot/sessions/:id/revoke", { preHandler: requireOwnerMutation }, async (request, reply) => { const software = findSoftware(db, request.params.software_slot); const result = db.prepare("UPDATE client_sessions SET revoked_at=? WHERE id=? AND software_id=? AND revoked_at IS NULL").run(nowIso(), request.params.id, software.id); if (!result.changes) return reply.code(404).send({ error: "NOT_FOUND" }); return { ok: true }; });

  app.get("/api/admin/software/:software_slot/announcement", { preHandler: requireAdmin }, async (request) => {
    return announcementPublic(findSoftware(db, request.params.software_slot), masterSecret);
  });
  app.put("/api/admin/software/:software_slot/announcement", { preHandler: requireOperatorMutation }, async (request, reply) => {
    const software = findSoftware(db, request.params.software_slot);
    const body = request.body || {};
    const value = Object.hasOwn(body, "announcement") ? body.announcement : body.text;
    if (typeof value !== "string" || value.length > MAX_DATA_STORE_BYTES) return reply.code(400).send({ error: "INVALID_ANNOUNCEMENT" });
    const updatedAt = nowIso();
    db.prepare("UPDATE software_slots SET announcement_encrypted=?,announcement_text='',announcement_updated_at=?,updated_at=? WHERE id=?")
      .run(encryptAtRest(masterSecret, value), updatedAt, updatedAt, software.id);
    audit(db, { userId: request.auth.userId, action: "update", objectType: "announcement", softwareId: software.id });
    return announcementPublic(db.prepare("SELECT * FROM software_slots WHERE id=?").get(software.id), masterSecret);
  });
  app.get("/api/admin/software/:software_slot/variables", { preHandler: requireAdmin }, async (request) => { const software = findSoftware(db, request.params.software_slot); return { items: db.prepare("SELECT * FROM software_variables WHERE software_id=? ORDER BY var_key").all(software.id).map((row) => ({ id: row.id, key: row.var_key, value: decryptAtRest(masterSecret, row.value_encrypted), version: row.version, enabled: Boolean(row.enabled), createdAt: row.created_at, updatedAt: row.updated_at })) }; });
  app.post("/api/admin/software/:software_slot/variables", { preHandler: requireOperatorMutation }, async (request, reply) => { const software = findSoftware(db, request.params.software_slot); const body = request.body || {}; if (typeof body.key !== "string" || !VAR_KEY_PATTERN.test(body.key)) return reply.code(400).send({ error: "INVALID_KEY" }); if (jsonBodySize(body.value) > MAX_REPORT_BYTES) return reply.code(413).send({ error: "VALUE_TOO_LARGE" }); try { const now = nowIso(); db.prepare("INSERT INTO software_variables(software_id,var_key,value_encrypted,version,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?)").run(software.id, body.key, encryptAtRest(masterSecret, body.value), 1, body.enabled === false ? 0 : 1, now, now); return { ok: true }; } catch { return reply.code(409).send({ error: "KEY_EXISTS" }); } });
  app.patch("/api/admin/software/:software_slot/variables/:id", { preHandler: requireOperatorMutation }, async (request, reply) => { const software = findSoftware(db, request.params.software_slot); const row = db.prepare("SELECT * FROM software_variables WHERE id=? AND software_id=?").get(Number(request.params.id), software.id); if (!row) return reply.code(404).send({ error: "NOT_FOUND" }); const body = request.body || {}; const key = typeof body.key === "string" && VAR_KEY_PATTERN.test(body.key) ? body.key : row.var_key; const changed = Object.hasOwn(body, "value"); const value = changed ? encryptAtRest(masterSecret, body.value) : row.value_encrypted; if (changed && jsonBodySize(body.value) > MAX_REPORT_BYTES) return reply.code(413).send({ error: "VALUE_TOO_LARGE" }); db.prepare("UPDATE software_variables SET var_key=?,value_encrypted=?,version=?,enabled=?,updated_at=? WHERE id=?").run(key, value, changed ? row.version + 1 : row.version, Object.hasOwn(body, "enabled") ? (body.enabled ? 1 : 0) : row.enabled, nowIso(), row.id); return { ok: true }; });
  app.delete("/api/admin/software/:software_slot/variables/:id", { preHandler: requireOperatorMutation }, async (request, reply) => { const software = findSoftware(db, request.params.software_slot); const result = db.prepare("DELETE FROM software_variables WHERE id=? AND software_id=?").run(Number(request.params.id), software.id); if (!result.changes) return reply.code(404).send({ error: "NOT_FOUND" }); return { ok: true }; });
  app.get("/api/admin/software/:software_slot/data-slots", { preHandler: requireAdmin }, async (request, reply) => {
    reply.header("cache-control", "no-store"); const software = findSoftware(db, request.params.software_slot); return { items: db.prepare("SELECT * FROM data_slots WHERE software_id=? ORDER BY id").all(software.id).map((row) => ({ id: row.id, slug: row.slug, name: row.name, description: row.description, enabled: Boolean(row.enabled) })), quotaBytes: FIXED_SLOT_QUOTA_BYTES }; });
  app.post("/api/admin/software/:software_slot/data-slots", { preHandler: requireOperatorMutation }, async (request, reply) => {
    const software = findSoftware(db, request.params.software_slot);
    const b = request.body || {};
    const slug = String(b.slug || "").toLowerCase();
    if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(slug) || typeof b.name !== "string" || !b.name.trim()) return reply.code(400).send({ error: "INVALID_DATA_SLOT" });
    try {
      const now = nowIso();
      const result = db.prepare("INSERT INTO data_slots(software_id,slug,name,description,enabled,single_limit,rolling_24h_limit,permanent_limit,max_records,retention_days,created_at,updated_at) VALUES(?,?,?,?,?,0,0,0,0,90,?,?)").run(software.id, slug, b.name.trim().slice(0, 128), String(b.description || "").slice(0, 1000), b.enabled === false ? 0 : 1, now, now);
      const row = db.prepare("SELECT * FROM data_slots WHERE id=?").get(result.lastInsertRowid);
      audit(db, { userId: request.auth.userId, action: "create", objectType: "data_slot", objectId: row.id, softwareId: software.id, metadata: { slug } });
      return { dataSlot: { id: row.id, slug: row.slug, name: row.name, description: row.description, enabled: Boolean(row.enabled) }, quotaBytes: FIXED_SLOT_QUOTA_BYTES };
    } catch { return reply.code(409).send({ error: "DATA_SLOT_EXISTS" }); }
  });
  app.get("/api/admin/software/:software_slot/data-slots/usage", { preHandler: requireAdmin }, async (request) => {
    const software = findSoftware(db, request.params.software_slot);
    const rows = db.prepare(`SELECT d.id,d.slug,d.name,d.enabled,
      COALESCE((SELECT SUM(s.size) FROM data_store s WHERE s.software_id=d.software_id AND s.slot_id=d.id),0) AS used_bytes,
      COALESCE((SELECT COUNT(*) FROM data_store s WHERE s.software_id=d.software_id AND s.slot_id=d.id),0) AS record_count,
      (SELECT MAX(s.updated_at) FROM data_store s WHERE s.software_id=d.software_id AND s.slot_id=d.id) AS last_received_at
      FROM data_slots d WHERE d.software_id=? ORDER BY d.id`).all(software.id);
    return { items: rows.map((row) => ({ slotId: row.id, slug: row.slug, name: row.name, enabled: Boolean(row.enabled), usedBytes: Number(row.used_bytes), recordCount: Number(row.record_count), lastReceivedAt: row.last_received_at || null, quotaBytes: MAX_DATA_STORE_BYTES, updatedAt: nowIso() })) };
  });
  app.patch("/api/admin/software/:software_slot/data-slots/:id", { preHandler: requireOperatorMutation }, async (request, reply) => { const software = findSoftware(db, request.params.software_slot); const row = db.prepare("SELECT * FROM data_slots WHERE id=? AND software_id=?").get(Number(request.params.id), software.id); if (!row) return reply.code(404).send({ error: "NOT_FOUND" }); const b = request.body || {}; db.prepare("UPDATE data_slots SET name=?,description=?,enabled=?,updated_at=? WHERE id=?").run(typeof b.name === "string" && b.name.trim() ? b.name.trim().slice(0, 128) : row.name, typeof b.description === "string" ? b.description.slice(0, 1000) : row.description, Object.hasOwn(b, "enabled") ? (b.enabled ? 1 : 0) : row.enabled, nowIso(), row.id); return { ok: true }; });
  app.delete("/api/admin/software/:software_slot/data-slots/:id", { preHandler: requireOperatorMutation }, async (request, reply) => {
    const software = findSoftware(db, request.params.software_slot); const id = Number(request.params.id);
    const row = db.prepare("SELECT * FROM data_slots WHERE id=? AND software_id=?").get(id, software.id);
    if (!row) return reply.code(404).send({ error: "NOT_FOUND" });
    const force = String(request.query?.force || "") === "true";
    const count = Number(db.prepare("SELECT COUNT(*) AS count FROM data_uploads WHERE slot_id=?").get(id).count);
    if (count > 0 && !force) return reply.code(409).send({ error: "DATA_SLOT_IN_USE", requiresForce: true, records: count });
    transaction(db, () => {
      db.prepare("DELETE FROM ingest_events WHERE slot_id=?").run(id);
      db.prepare("DELETE FROM data_uploads WHERE slot_id=?").run(id);
      db.prepare("DELETE FROM data_store WHERE slot_id=?").run(id);
      db.prepare("DELETE FROM data_usage WHERE slot_id=?").run(id);
      db.prepare("DELETE FROM data_slots WHERE id=? AND software_id=?").run(id, software.id);
    });
    audit(db, { userId: request.auth.userId, action: "delete", objectType: "data_slot", objectId: id, softwareId: software.id, metadata: { slug: row.slug, force, records: count } });
    return { ok: true, deletedRecords: count };
  });

  app.delete("/api/admin/software/:software_slot/data-slots/:slot/history", { preHandler: requireOperatorMutation }, async (request, reply) => {
    const software = findSoftware(db, request.params.software_slot);
    const slot = findDataSlot(db, software, request.params.slot, true);
    const deletedAt = nowIso();
    const result = transaction(db, () => {
      const rows = db.prepare("SELECT id,size,license_id FROM data_uploads WHERE software_id=? AND slot_id=? AND status='received'").all(software.id, slot.id);
      db.prepare("UPDATE data_uploads SET status='deleted' WHERE software_id=? AND slot_id=? AND status='received'").run(software.id, slot.id);
      db.prepare("DELETE FROM data_usage WHERE software_id=? AND slot_id=?").run(software.id, slot.id);
      return rows;
    });
    audit(db, { userId: request.auth.userId, action: "clear_history", objectType: "data_slot_history", objectId: slot.id, softwareId: software.id, metadata: { slug: slot.slug, count: result.length } });
    return { ok: true, deleted: result.length, clearedAt: deletedAt };
  });

  app.get("/api/admin/software/:software_slot/data-store", { preHandler: requireAdmin }, async (request, reply) => {
    try {
      const software = findSoftware(db, request.params.software_slot);
      return { items: listDataStoreRows(db, masterSecret, software, request.query || {}) };
    } catch (error) {
      if (error instanceof ApiError) return reply.code(error.status).send({ error: error.code });
      throw error;
    }
  });
  app.delete("/api/admin/software/:software_slot/data-store/:id", { preHandler: requireOperatorMutation }, async (request, reply) => {
    const software = findSoftware(db, request.params.software_slot);
    const id = Number(request.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return reply.code(400).send({ error: "INVALID_DATA" });
    const row = db.prepare("SELECT * FROM data_store WHERE id=? AND software_id=?").get(id, software.id);
    if (!row) return reply.code(404).send({ error: "NOT_FOUND" });
    transaction(db, () => {
      db.prepare("DELETE FROM data_store WHERE id=? AND software_id=?").run(id, software.id);
      db.prepare("DELETE FROM data_usage WHERE software_id=? AND slot_id=? AND license_id=?").run(software.id, row.slot_id, row.license_id);
    });
    audit(db, { userId: request.auth.userId, action: "delete", objectType: "data_store", objectId: id, softwareId: software.id });
    return { ok: true };
  });

  app.get("/api/admin/software/:software_slot/data/:licenseId/:slot", { preHandler: requireAdmin }, async (request, reply) => {
    try {
      const software = findSoftware(db, request.params.software_slot);
      const licenseId = Number(request.params.licenseId);
      if (!Number.isSafeInteger(licenseId) || licenseId < 1) return reply.code(400).send({ error: "INVALID_LICENSE" });
      const license = db.prepare("SELECT id FROM license_codes WHERE id=? AND software_id=?").get(licenseId, software.id);
      if (!license) return reply.code(404).send({ error: "NOT_FOUND" });
      const slot = findDataSlot(db, software, request.params.slot, true);
      const row = db.prepare(`SELECT s.*,d.slug AS slot_slug,l.public_id
        FROM data_store s JOIN data_slots d ON d.id=s.slot_id AND d.software_id=s.software_id
        JOIN license_codes l ON l.id=s.license_id AND l.software_id=s.software_id
        WHERE s.software_id=? AND s.slot_id=? AND s.license_id=?`).get(software.id, slot.id, licenseId);
      if (!row) return reply.code(404).send({ error: "NOT_FOUND" });
      return { data: dataStorePublic(masterSecret, row) };
    } catch (error) {
      if (error instanceof ApiError) return reply.code(error.status).send({ error: error.code });
      throw error;
    }
  });
  app.put("/api/admin/software/:software_slot/data/:licenseId/:slot", { preHandler: requireOperatorMutation }, async (request, reply) => {
    try {
      const software = findSoftware(db, request.params.software_slot);
      const licenseId = Number(request.params.licenseId);
      if (!Number.isSafeInteger(licenseId) || licenseId < 1) return reply.code(400).send({ error: "INVALID_LICENSE" });
      const license = db.prepare("SELECT id FROM license_codes WHERE id=? AND software_id=?").get(licenseId, software.id);
      if (!license) return reply.code(404).send({ error: "NOT_FOUND" });
      const slot = findDataSlot(db, software, request.params.slot, true);
      const body = request.body || {};
      const mode = body.mode || "overwrite";
      const result = writeDataStore(db, masterSecret, software, licenseId, slot, body.data, mode);
      const row = db.prepare(`SELECT s.*,d.slug AS slot_slug,l.public_id
        FROM data_store s JOIN data_slots d ON d.id=s.slot_id AND d.software_id=s.software_id
        JOIN license_codes l ON l.id=s.license_id AND l.software_id=s.software_id
        WHERE s.id=? AND s.software_id=?`).get(result.id, software.id);
      return { data: dataStorePublic(masterSecret, row), result };
    } catch (error) {
      if (error instanceof ApiError) return reply.code(error.status).send({ error: error.code });
      throw error;
    }
  });
  app.delete("/api/admin/software/:software_slot/data/:licenseId/:slot", { preHandler: requireOperatorMutation }, async (request, reply) => {
    const software = findSoftware(db, request.params.software_slot);
    const licenseId = Number(request.params.licenseId);
    if (!Number.isSafeInteger(licenseId) || licenseId < 1) return reply.code(400).send({ error: "INVALID_LICENSE" });
    const slot = findDataSlot(db, software, request.params.slot, true);
    const result = db.prepare("DELETE FROM data_store WHERE software_id=? AND slot_id=? AND license_id=?").run(software.id, slot.id, licenseId);
    if (!result.changes) return reply.code(404).send({ error: "NOT_FOUND" });
    return { ok: true };
  });


  app.get("/api/admin/software/:software_slot/reports", { preHandler: requireAdmin }, async (request) => {
    const software = findSoftware(db, request.params.software_slot);
    const page = Math.max(1, Number(request.query?.page) || 1);
    const limit = safeLimit(request.query?.limit, 50, 200);
    const params = [software.id];
    let where = "u.software_id=? AND u.status='received'";
    if (request.query?.dataSlot || request.query?.slot) { where += " AND d.slug=?"; params.push(String(request.query.dataSlot || request.query.slot)); }
    if (request.query?.licenseId) { where += " AND u.license_id=?"; params.push(Number(request.query.licenseId)); }
    if (["received", "deleted"].includes(request.query?.status)) { where = where.replace("u.status='received'", "u.status=?"); params.splice(1, 0, request.query.status); }
    const total = Number(db.prepare(`SELECT COUNT(*) AS count FROM data_uploads u JOIN data_slots d ON d.id=u.slot_id WHERE ${where}`).get(...params).count);
    const rows = db.prepare(`SELECT u.*,d.slug AS slot_slug,l.public_id FROM data_uploads u JOIN data_slots d ON d.id=u.slot_id LEFT JOIN license_codes l ON l.id=u.license_id WHERE ${where} ORDER BY u.id DESC LIMIT ? OFFSET ?`).all(...params, limit, (page - 1) * limit);
    return { items: rows.map((row) => publicUpload(row, { includeSensitive: request.auth.role === "owner" })), page, limit, total };
  });
  app.get("/api/admin/software/:software_slot/reports/:id", { preHandler: requireAdmin }, async (request, reply) => {
    const software = findSoftware(db, request.params.software_slot);
    const row = db.prepare("SELECT u.*,d.slug AS slot_slug,l.public_id FROM data_uploads u JOIN data_slots d ON d.id=u.slot_id LEFT JOIN license_codes l ON l.id=u.license_id WHERE u.id=? AND u.software_id=? AND u.status='received'").get(Number(request.params.id), software.id);
    if (!row) return reply.code(404).send({ error: "NOT_FOUND" });
    const result = publicUpload(row, { includeSensitive: request.auth.role === "owner" });
    if (request.auth.role === "owner") result.payload = decryptAtRest(masterSecret, row.payload_encrypted);
    return result;
  });
  app.delete("/api/admin/software/:software_slot/reports/:id", { preHandler: requireOperatorMutation }, async (request, reply) => {
    const software = findSoftware(db, request.params.software_slot); const id = Number(request.params.id); const deletedAt = nowIso();
    const result = transaction(db, () => {
      const row = db.prepare("SELECT * FROM data_uploads WHERE id=? AND software_id=? AND status='received'").get(id, software.id);
      if (!row) return null;
      db.prepare("DELETE FROM data_uploads WHERE id=?").run(id);
      db.prepare("UPDATE data_usage SET permanent_bytes=MAX(0,permanent_bytes-?),records_count=MAX(0,records_count-1),updated_at=? WHERE software_id=? AND slot_id=? AND ((license_id=? ) OR (license_id IS NULL AND ? IS NULL))").run(row.size, deletedAt, software.id, row.slot_id, row.license_id, row.license_id);
      return row;
    });
    if (!result) return reply.code(404).send({ error: "NOT_FOUND" });
    audit(db, { userId: request.auth.userId, action: "delete", objectType: "report", objectId: id, softwareId: software.id });
    return { ok: true };
  });

  app.get("/api/admin/software/:software_slot/resources", { preHandler: requireAdmin }, async (request) => { const software = findSoftware(db, request.params.software_slot); return { items: db.prepare("SELECT * FROM software_resources WHERE software_id=? AND status='ready' ORDER BY id DESC").all(software.id).map(publicResource) }; });
  app.post("/api/admin/software/:software_slot/resources", { preHandler: requireOwnerMutation }, async (request, reply) => {
    const software = findSoftware(db, request.params.software_slot);
    const b = request.body || {};
    if (!b || typeof b !== "object" || Buffer.isBuffer(b) || b.file != null) return reply.code(415).send({ error: "JSON_BASE64_REQUIRED", message: "Use JSON with content as base64; FormData is not supported." });
    const originalName = typeof b.originalName === "string" ? b.originalName.trim().slice(0, 200) : "";
    if (!originalName || originalName.includes("/") || originalName.includes("\\") || originalName.includes("\0")) return reply.code(400).send({ error: "INVALID_FILE_NAME" });
    const content = parseBase64Content(b.content);
    if (content.length > MAX_FILE_BYTES) return reply.code(413).send({ error: "FILE_TOO_LARGE" });
    ensureStorageAvailable();
    const storageName = `${randomToken(18)}.bin`;
    const softwareDir = join(FILES_ROOT, "resources", String(software.id));
    mkdirSync(softwareDir, { recursive: true, mode: 0o700 });
    try { chmodSync(softwareDir, 0o700); } catch {}
    const target = resolve(softwareDir, storageName);
    const temp = `${target}.${randomToken(8)}.tmp`;
    writeFileSync(temp, content, { mode: 0o600, flag: "wx" });
    try { renameSync(temp, target); } catch (error) { try { unlinkSync(temp); } catch {} throw error; }
    const digest = sha256(content);
    let result;
    try {
      result = db.prepare("INSERT INTO software_resources(software_id,original_name,storage_name,storage_path,sha256,size,mime,status,created_at) VALUES(?,?,?,?,?,?,?,'ready',?)").run(software.id, originalName, storageName, `resources/${software.id}/${storageName}`, digest, content.length, typeof b.mime === "string" ? b.mime.slice(0, 120) : "application/octet-stream", nowIso());
    } catch (error) { try { unlinkSync(target); } catch {} throw error; }
    audit(db, { userId: request.auth.userId, action: "upload", objectType: "resource", objectId: Number(result.lastInsertRowid), softwareId: software.id, metadata: { name: originalName, size: content.length } });
    return { resource: publicResource(db.prepare("SELECT * FROM software_resources WHERE id=?").get(result.lastInsertRowid)) };
  });
  app.delete("/api/admin/software/:software_slot/resources/:id", { preHandler: requireOwnerMutation }, async (request, reply) => {
    const software = findSoftware(db, request.params.software_slot);
    const file = db.prepare("SELECT * FROM software_resources WHERE id=? AND software_id=? AND status='ready'").get(Number(request.params.id), software.id);
    if (!file) return reply.code(404).send({ error: "NOT_FOUND" });
    db.prepare("UPDATE software_resources SET status='deleted' WHERE id=?").run(file.id);
    try { const target = safeResourcePath(file); unlinkSync(target); } catch {}
    audit(db, { userId: request.auth.userId, action: "delete", objectType: "resource", objectId: file.id, softwareId: software.id, metadata: { name: file.original_name } });
    return { ok: true };
  });
  app.post("/api/admin/software/:software_slot/uploads", { preHandler: requireOwnerMutation, bodyLimit: 256 * 1024 }, async (request, reply) => {
    const software = findSoftware(db, request.params.software_slot);
    const body = request.body || {};
    const originalName = typeof body.originalName === "string" ? body.originalName.trim().slice(0, 200) : "";
    const declaredSize = Number(body.size);
    if (!originalName || originalName.includes("/") || originalName.includes("\\") || originalName.includes("\0") || !Number.isSafeInteger(declaredSize) || declaredSize < 1) return reply.code(400).send({ error: "INVALID_UPLOAD" });
    const uploadId = randomToken(18);
    const uploadDir = join(FILES_ROOT, "uploads");
    mkdirSync(uploadDir, { recursive: true, mode: 0o700 });
    const tempPath = join(uploadDir, `${uploadId}.part`);
    writeFileSync(tempPath, Buffer.alloc(0), { mode: 0o600, flag: "wx" });
    const now = nowIso();
    db.prepare(`INSERT INTO resource_uploads(id,software_id,created_by,original_name,mime,declared_size,declared_sha256,temp_path,received_bytes,status,expires_at,created_at,updated_at)
      VALUES(?,?,?,?,?,?,?,?,0,'receiving',?,?,?)`).run(uploadId, software.id, request.auth.userId, originalName, typeof body.mime === "string" ? body.mime.slice(0, 120) : "application/octet-stream", declaredSize, typeof body.sha256 === "string" ? body.sha256.toLowerCase() : null, tempPath, new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(), now, now);
    return { uploadId, offset: 0, expiresAt: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString() };
  });
  app.put("/api/admin/software/:software_slot/uploads/:id", { preHandler: requireOwnerMutation, bodyLimit: 8 * 1024 * 1024 }, async (request, reply) => {
    const software = findSoftware(db, request.params.software_slot);
    const upload = db.prepare("SELECT * FROM resource_uploads WHERE id=? AND software_id=? AND status='receiving'").get(request.params.id, software.id);
    if (!upload || new Date(upload.expires_at).getTime() <= Date.now()) return reply.code(404).send({ error: "UPLOAD_NOT_FOUND" });
    const offset = Number(request.headers["x-upload-offset"] ?? request.query?.offset ?? 0);
    const chunk = Buffer.isBuffer(request.body) ? request.body : Buffer.from(request.body || "");
    if (!Number.isSafeInteger(offset) || offset !== Number(upload.received_bytes) || !chunk.length || Number(upload.received_bytes) + chunk.length > Number(upload.declared_size)) return reply.code(409).send({ error: "UPLOAD_OFFSET_MISMATCH", expectedOffset: upload.received_bytes });
    ensureStorageAvailable();
    const fd = openSync(upload.temp_path, "a");
    try { writeFileSync(fd, chunk); } finally { closeSync(fd); }
    const received = Number(upload.received_bytes) + chunk.length;
    db.prepare("UPDATE resource_uploads SET received_bytes=?,updated_at=? WHERE id=?").run(received, nowIso(), upload.id);
    return { uploadId: upload.id, offset: received, complete: received === Number(upload.declared_size) };
  });
  app.post("/api/admin/software/:software_slot/uploads/:id/complete", { preHandler: requireOwnerMutation, bodyLimit: 64 * 1024 }, async (request, reply) => {
    const software = findSoftware(db, request.params.software_slot);
    const upload = db.prepare("SELECT * FROM resource_uploads WHERE id=? AND software_id=? AND status='receiving'").get(request.params.id, software.id);
    if (!upload || Number(upload.received_bytes) !== Number(upload.declared_size)) return reply.code(409).send({ error: "UPLOAD_INCOMPLETE", expectedOffset: upload?.received_bytes || 0 });
    const content = readFileSync(upload.temp_path);
    const digest = sha256(content);
    if (upload.declared_sha256 && upload.declared_sha256 !== digest) return reply.code(422).send({ error: "UPLOAD_DIGEST_MISMATCH" });
    ensureStorageAvailable();
    const storageName = `${randomToken(18)}.bin`;
    const softwareDir = join(FILES_ROOT, "resources", String(software.id));
    mkdirSync(softwareDir, { recursive: true, mode: 0o700 });
    const target = resolve(softwareDir, storageName);
    renameSync(upload.temp_path, target);
    const now = nowIso();
    const inserted = db.prepare("INSERT INTO software_resources(software_id,original_name,storage_name,storage_path,sha256,size,mime,status,created_at) VALUES(?,?,?,?,?,?,?,'ready',?)").run(software.id, upload.original_name, storageName, `resources/${software.id}/${storageName}`, digest, content.length, upload.mime, now);
    db.prepare("UPDATE resource_uploads SET status='completed',updated_at=? WHERE id=?").run(now, upload.id);
    audit(db, { userId: request.auth.userId, action: "upload_complete", objectType: "resource", objectId: Number(inserted.lastInsertRowid), softwareId: software.id, metadata: { size: content.length } });
    return { resource: publicResource(db.prepare("SELECT * FROM software_resources WHERE id=?").get(inserted.lastInsertRowid)), uploadId: upload.id };
  });
  app.delete("/api/admin/software/:software_slot/uploads/:id", { preHandler: requireOwnerMutation }, async (request, reply) => {
    const software = findSoftware(db, request.params.software_slot);
    const upload = db.prepare("SELECT * FROM resource_uploads WHERE id=? AND software_id=? AND status='receiving'").get(request.params.id, software.id);
    if (!upload) return reply.code(404).send({ error: "UPLOAD_NOT_FOUND" });
    db.prepare("UPDATE resource_uploads SET status='cancelled',updated_at=? WHERE id=?").run(nowIso(), upload.id);
    try { unlinkSync(upload.temp_path); } catch {}
    return { ok: true };
  });
  app.get("/api/admin/software/:software_slot/monitoring", { preHandler: requireAdmin }, async (request) => { const software = findSoftware(db, request.params.software_slot); const since = new Date(Date.now() - 60 * 60 * 1000).toISOString(); const activeSessions = db.prepare("SELECT COUNT(*) AS count FROM client_sessions WHERE software_id=? AND revoked_at IS NULL AND expires_at>? AND last_heartbeat_at>?").get(software.id, nowIso(), new Date(Date.now() - software.heartbeat_timeout * 1000).toISOString()).count; const staleSessions = db.prepare("SELECT COUNT(*) AS count FROM client_sessions WHERE software_id=? AND revoked_at IS NULL AND last_heartbeat_at<=?").get(software.id, new Date(Date.now() - software.heartbeat_timeout * 1000).toISOString()).count; return { software: software.slug, requestsLastHour: db.prepare("SELECT COUNT(*) AS count FROM data_uploads WHERE software_id=? AND received_at>=?").get(software.id, since).count, reportsLastHour: db.prepare("SELECT COUNT(*) AS count FROM data_uploads WHERE software_id=? AND received_at>=?").get(software.id, since).count, activeSessions, staleSessions, memory: process.memoryUsage(), cpu: process.cpuUsage(), loadAverage: os.loadavg(), storage: (() => { try { const s = statfsSync(FILES_ROOT); return { freeBytes: Number(s.bavail) * Number(s.bsize), totalBytes: Number(s.blocks) * Number(s.bsize) }; } catch { return null; } })(), sqlite: { journalMode: "WAL" }, generatedAt: nowIso() }; });
  app.get("/api/admin/software/:software_slot/security", { preHandler: requireAdmin }, async (request) => {
    const software = findSoftware(db, request.params.software_slot);
    return { security: { protocolVersion: "jur10n-client-v2", machineCheck: Boolean(software.machine_check), ipCheck: Boolean(software.ip_check), ipChangePolicy: software.ip_change_policy, heartbeatTimeout: software.heartbeat_timeout, sessionTtl: software.session_ttl } };
  });
  app.put("/api/admin/software/:software_slot/security", { preHandler: requireOwnerMutation }, async (request, reply) => {
    const software = findSoftware(db, request.params.software_slot);
    const body = request.body || {};
    if (body.protocolVersion != null && body.protocolVersion !== "jur10n-client-v2") return reply.code(400).send({ error: "INVALID_PROTOCOL" });
    const next = {
      machineCheck: Object.hasOwn(body, "machineCheck") ? (body.machineCheck ? 1 : 0) : software.machine_check,
      ipCheck: Object.hasOwn(body, "ipCheck") ? (body.ipCheck ? 1 : 0) : software.ip_check,
      ipChangePolicy: ["deny", "update", "allow"].includes(body.ipChangePolicy) ? body.ipChangePolicy : software.ip_change_policy,
      heartbeatTimeout: Object.hasOwn(body, "heartbeatTimeout") ? Math.min(3600, Math.max(30, Number(body.heartbeatTimeout) || 300)) : software.heartbeat_timeout,
      sessionTtl: Object.hasOwn(body, "sessionTtl") ? Math.min(2592000, Math.max(60, Number(body.sessionTtl) || 604800)) : software.session_ttl,
    };
    db.prepare("UPDATE software_slots SET machine_check=?,ip_check=?,ip_change_policy=?,heartbeat_timeout=?,session_ttl=?,updated_at=? WHERE id=?").run(next.machineCheck, next.ipCheck, next.ipChangePolicy, next.heartbeatTimeout, next.sessionTtl, nowIso(), software.id);
    return { security: { protocolVersion: "jur10n-client-v2", ...next, machineCheck: Boolean(next.machineCheck), ipCheck: Boolean(next.ipCheck) } };
  });

  app.get("/api/admin/custom", { preHandler: requireOwnerMutation }, async () => ({
    enabled: true,
    routes: [{ name: "custom placeholder", path: "/api/custom/*", status: "reserved", editableVia: "SSH" }],
    message: "Custom API area is reserved for explicit server-side modules. No dynamic code execution is enabled.",
  }));
  app.get("/api/custom/healthz", async () => ({ ok: true, area: "custom", status: "reserved", time: nowIso() }));

  // VPN 模块：返回 vpn/generate.mjs 生成的订阅链接与节点元数据（仅管理员可见）。
  app.get("/api/admin/vpn", { preHandler: requireAdmin }, async () => {
    const metaPath = process.env.VPN_META_PATH || "/srv/jur10n/data/vpn/meta.json";
    try {
      const meta = JSON.parse(readFileSync(metaPath, "utf8"));
      return {
        vpn: {
          enabled: meta.enabled !== false,
          name: typeof meta.name === "string" ? meta.name : "",
          server: typeof meta.server === "string" ? meta.server : "",
          subscriptionUrl: typeof meta.subscriptionUrl === "string" ? meta.subscriptionUrl : "",
          updatedAt: typeof meta.updatedAt === "string" ? meta.updatedAt : null,
          nodes: Array.isArray(meta.nodes) ? meta.nodes : [],
        },
      };
    } catch {
      return { vpn: { enabled: false, name: null, server: null, subscriptionUrl: null, updatedAt: null, nodes: [], message: "VPN 订阅尚未生成：在服务端运行 vpn/generate.mjs 后执行 vpn/deploy.sh。" } };
    }
  });

  app.get("/api/admin/monitoring", { preHandler: requireAdmin }, async () => {
    const since = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    const slots = db.prepare("SELECT * FROM software_slots ORDER BY id").all();
    const items = slots.map((software) => {
      const stale = new Date(Date.now() - Number(software.heartbeat_timeout || CLIENT_HEARTBEAT_TIMEOUT_SECONDS) * 1000).toISOString();
      return {
        slug: software.slug,
        name: software.name,
        status: software.status,
        requestsLastHour: Number(db.prepare("SELECT COUNT(*) AS count FROM data_uploads WHERE software_id=? AND received_at>=?").get(software.id, since).count),
        activeSessions: Number(db.prepare("SELECT COUNT(*) AS count FROM client_sessions WHERE software_id=? AND revoked_at IS NULL AND expires_at>? AND last_heartbeat_at>?").get(software.id, nowIso(), stale).count),
        staleSessions: Number(db.prepare("SELECT COUNT(*) AS count FROM client_sessions WHERE software_id=? AND revoked_at IS NULL AND expires_at>? AND last_heartbeat_at<=?").get(software.id, nowIso(), stale).count),
        licenses: Number(db.prepare("SELECT COUNT(*) AS count FROM license_codes WHERE software_id=?").get(software.id).count),
      };
    });
    let storage = null;
    try { const stat = statfsSync(FILES_ROOT); storage = { freeBytes: Number(stat.bavail) * Number(stat.bsize), totalBytes: Number(stat.blocks) * Number(stat.bsize) }; } catch {}
    return {
      totals: {
        requestsLastHour: items.reduce((sum, item) => sum + item.requestsLastHour, 0),
        activeSessions: items.reduce((sum, item) => sum + item.activeSessions, 0),
        staleSessions: items.reduce((sum, item) => sum + item.staleSessions, 0),
        licenses: items.reduce((sum, item) => sum + item.licenses, 0),
        softwareCount: items.length,
      },
      items,
      memory: process.memoryUsage(),
      cpu: process.cpuUsage(),
      loadAverage: os.loadavg(),
      storage,
      sqlite: { journalMode: "wal" },
      generatedAt: nowIso(),
    };
  });
  app.get("/api/admin/software/:software_slot/docs", { preHandler: requireAdmin }, async (request, reply) => { try { const software = findSoftware(db, request.params.software_slot); return { title: "jur10n client protocol v2", description: "Per-software AES-256-GCM client protocol.", protocol: "jur10n-client-v2", endpoint: `/api/v2/client/${software.slug}`, contentType: "application/octet-stream", timestampWindowMs: CLIENT_TIMESTAMP_WINDOW_MS, packetLimitBytes: MAX_CLIENT_PACKET_BYTES, reportLimitBytes: MAX_REPORT_BYTES, slotQuotaBytes: FIXED_SLOT_QUOTA_BYTES, heartbeatTimeoutSeconds: software.heartbeat_timeout, operations: [...ALLOWED_OPS].map((op) => ({ op })), errorCodes: ["INVALID_REQUEST", "INVALID_PROTOCOL", "INVALID_OPERATION", "INVALID_KEY_VERSION", "INVALID_MACHINE_PROOF", "TIMESTAMP_INVALID", "REPLAY_DETECTED", "INVALID_CREDENTIALS", "INVALID_LICENSE_CODE", "LICENSE_EXPIRED", "MACHINE_PROOF_REQUIRED", "MACHINE_MISMATCH", "IP_MISMATCH", "DEVICE_LIMIT", "SESSION_REQUIRED", "SESSION_REVOKED", "SESSION_EXPIRED", "SESSION_INACTIVE", "KEY_REVOKED", "KEY_ALREADY_EXPORTED", "SOFTWARE_DISABLED", "DATA_SLOT_NOT_FOUND", "RECEIVING_DISABLED", "PAYLOAD_TOO_LARGE", "QUOTA_EXCEEDED", "STORAGE_LIMIT", "INVALID_OFFSET", "FILE_NOT_FOUND", "RATE_LIMITED"].map((code) => ({ code })), aad: { request: `jur10n:client:v2:${software.slug}:{key_version}:request`, response: `jur10n:client:v2:${software.slug}:{key_version}:response` }, software: softwarePublic(db, software) }; } catch (error) { if (error instanceof ApiError) return reply.code(error.status).send({ error: error.code }); throw error; } });

  app.get("/api/admin/security", { preHandler: requireAdmin }, async () => ({ perMinute: Number(getSetting(db, "client_rate_limit_per_minute", 30)), loginPerMinute: Number(getSetting(db, "login_rate_limit_per_minute", 10)), maxClientPacketBytes: MAX_CLIENT_PACKET_BYTES, maxUploadBytes: MAX_REPORT_BYTES, diskLowWatermarkBytes: Number(process.env.MIN_FREE_BYTES || 256 * 1024 * 1024) }));
  app.put("/api/admin/security", { preHandler: requireOperatorMutation }, async (request, reply) => { const body = request.body || {}; const perMinute = body.perMinute == null ? Number(getSetting(db, "client_rate_limit_per_minute", 30)) : Number(body.perMinute); const loginPerMinute = body.loginPerMinute == null ? Number(getSetting(db, "login_rate_limit_per_minute", 10)) : Number(body.loginPerMinute); if (!Number.isInteger(perMinute) || perMinute < 1 || perMinute > 10000 || !Number.isInteger(loginPerMinute) || loginPerMinute < 1 || loginPerMinute > 100) return reply.code(400).send({ error: "INVALID_RATE_LIMIT" }); setSetting(db, "client_rate_limit_per_minute", perMinute); setSetting(db, "login_rate_limit_per_minute", loginPerMinute); return { perMinute, loginPerMinute, maxClientPacketBytes: MAX_CLIENT_PACKET_BYTES, maxUploadBytes: MAX_REPORT_BYTES, diskLowWatermarkBytes: Number(process.env.MIN_FREE_BYTES || 256 * 1024 * 1024) }; });

  app.get("/api/admin/overview", { preHandler: requireAdmin }, async () => { const today = new Date(); today.setUTCHours(0, 0, 0, 0); return { licenses: db.prepare("SELECT COUNT(*) AS count FROM license_keys").get().count + db.prepare("SELECT COUNT(*) AS count FROM license_codes WHERE software_id<>(SELECT id FROM software_slots WHERE slug='legacy')").get().count, activeLicenses: db.prepare("SELECT COUNT(*) AS count FROM license_keys WHERE status='active' AND (expires_at IS NULL OR expires_at>?)").get(nowIso()).count, variables: db.prepare("SELECT COUNT(*) AS count FROM variables WHERE enabled=1").get().count, reportsToday: db.prepare("SELECT COUNT(*) AS count FROM reports WHERE received_at>=?").get(today.toISOString()).count, reports: db.prepare("SELECT COUNT(*) AS count FROM reports").get().count, activeSessions: db.prepare("SELECT COUNT(*) AS count FROM client_sessions WHERE revoked_at IS NULL AND expires_at>?").get(nowIso()).count }; });
  app.get("/api/admin/licenses", { preHandler: requireAdmin }, async (request) => { const legacySoftware = findSoftware(db, "legacy"); return listScopedLicenses(legacySoftware, request.query || {}); });
  app.post("/api/admin/licenses", { preHandler: requireOperatorMutation }, async (request) => { request.params = { software_slot: "legacy" }; const software = findSoftware(db, "legacy"); const body = request.body || {}; const count = Math.min(1000, Math.max(1, Number(body.count) || 1)); const prefix = normalizeLicensePrefix(body.prefix); const expiresAt = validIso(body.expiresAt); const maxDevices = Math.min(100, Math.max(1, Number(body.maxDevices) || 1)); const note = typeof body.note === "string" ? body.note.slice(0, 500) : ""; const codes = []; transaction(db, () => { for (let i = 0; i < count; i += 1) { const code = generatedLicenseCode(prefix); db.prepare("INSERT INTO license_codes(software_id,code_hash,code_encrypted,public_id,status,expires_at,max_devices,note,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)").run(software.id, clientCodeHash(masterSecret, code), encryptAtRest(masterSecret, code), randomToken(12), "active", expiresAt, maxDevices, note, nowIso(), nowIso()); codes.push(code); } }); return { codes, count }; });
  app.patch("/api/admin/licenses/:id", { preHandler: requireOperatorMutation }, async (request, reply) => { const row = db.prepare("SELECT * FROM license_keys WHERE id=?").get(Number(request.params.id)); if (!row) return reply.code(404).send({ error: "NOT_FOUND" }); const legacy = findSoftware(db, "legacy"); const scoped = db.prepare("SELECT * FROM license_codes WHERE software_id=? AND public_id=?").get(legacy.id, row.public_id); if (scoped) { db.prepare("UPDATE license_codes SET status=?,expires_at=?,note=?,max_devices=?,updated_at=? WHERE id=?").run(request.body?.status === "revoked" ? "revoked" : request.body?.status === "active" ? "active" : scoped.status, Object.hasOwn(request.body || {}, "expiresAt") ? validIso(request.body.expiresAt) : scoped.expires_at, typeof request.body?.note === "string" ? request.body.note : scoped.note, Number(request.body?.maxDevices) || scoped.max_devices, nowIso(), scoped.id); } db.prepare("UPDATE license_keys SET status=?,expires_at=?,note=?,max_devices=? WHERE id=?").run(request.body?.status === "revoked" ? "revoked" : request.body?.status === "active" ? "active" : row.status, Object.hasOwn(request.body || {}, "expiresAt") ? validIso(request.body.expiresAt) : row.expires_at, typeof request.body?.note === "string" ? request.body.note : row.note, Number(request.body?.maxDevices) || row.max_devices, row.id); return { ok: true }; });
  app.delete("/api/admin/licenses/:id", { preHandler: requireOperatorMutation }, async (request, reply) => { const result = db.prepare("UPDATE license_keys SET status='revoked' WHERE id=?").run(Number(request.params.id)); if (!result.changes) return reply.code(404).send({ error: "NOT_FOUND" }); const legacy = findSoftware(db, "legacy"); db.prepare("UPDATE license_codes SET status='revoked',updated_at=? WHERE software_id=? AND public_id=(SELECT public_id FROM license_keys WHERE id=? )").run(nowIso(), legacy.id, Number(request.params.id)); return { ok: true }; });
  app.get("/api/admin/variables", { preHandler: requireAdmin }, async () => ({ items: db.prepare("SELECT * FROM variables ORDER BY var_key").all().map((row) => ({ id: row.id, key: row.var_key, value: decryptAtRest(masterSecret, row.value_encrypted), version: row.version, enabled: Boolean(row.enabled), createdAt: row.created_at, updatedAt: row.updated_at })) }));
  app.post("/api/admin/variables", { preHandler: requireOperatorMutation }, async (request, reply) => { const body = request.body || {}; if (typeof body.key !== "string" || !VAR_KEY_PATTERN.test(body.key)) return reply.code(400).send({ error: "INVALID_KEY" }); try { const now = nowIso(); db.prepare("INSERT INTO variables(var_key,value_encrypted,version,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?)").run(body.key, encryptAtRest(masterSecret, body.value), 1, body.enabled === false ? 0 : 1, now, now); return { ok: true }; } catch { return reply.code(409).send({ error: "KEY_EXISTS" }); } });
  app.patch("/api/admin/variables/:id", { preHandler: requireOperatorMutation }, async (request, reply) => { const row = db.prepare("SELECT * FROM variables WHERE id=?").get(Number(request.params.id)); if (!row) return reply.code(404).send({ error: "NOT_FOUND" }); const changed = Object.hasOwn(request.body || {}, "value"); db.prepare("UPDATE variables SET var_key=?,value_encrypted=?,version=?,enabled=?,updated_at=? WHERE id=?").run(typeof request.body?.key === "string" ? request.body.key : row.var_key, changed ? encryptAtRest(masterSecret, request.body.value) : row.value_encrypted, changed ? row.version + 1 : row.version, Object.hasOwn(request.body || {}, "enabled") ? (request.body.enabled ? 1 : 0) : row.enabled, nowIso(), row.id); return { ok: true }; });
  app.delete("/api/admin/variables/:id", { preHandler: requireOperatorMutation }, async (request, reply) => { const result = db.prepare("DELETE FROM variables WHERE id=?").run(Number(request.params.id)); if (!result.changes) return reply.code(404).send({ error: "NOT_FOUND" }); return { ok: true }; });
  app.get("/api/admin/receive-settings", { preHandler: requireAdmin }, async () => ({ settings: getSetting(db, "receive_settings", { enabled: true, maxPayloadBytes: MAX_REPORT_BYTES }) }));
  app.put("/api/admin/receive-settings", { preHandler: requireOperatorMutation }, async (request, reply) => { const current = getSetting(db, "receive_settings", { enabled: true, maxPayloadBytes: MAX_REPORT_BYTES }); const settings = { enabled: request.body?.enabled == null ? current.enabled : Boolean(request.body.enabled), maxPayloadBytes: Math.min(MAX_REPORT_BYTES, Math.max(1024, Number(request.body?.maxPayloadBytes) || current.maxPayloadBytes)) }; setSetting(db, "receive_settings", settings); return { settings }; });
  app.get("/api/admin/security/rate-limit", { preHandler: requireAdmin }, async () => ({ perMinute: Number(getSetting(db, "client_rate_limit_per_minute", 30)) }));
  app.put("/api/admin/security/rate-limit", { preHandler: requireOperatorMutation }, async (request, reply) => { const perMinute = Number(request.body?.perMinute); if (!Number.isInteger(perMinute) || perMinute < 1 || perMinute > 10000) return reply.code(400).send({ error: "INVALID_RATE_LIMIT" }); setSetting(db, "client_rate_limit_per_minute", perMinute); return { perMinute }; });
  app.get("/api/admin/reports", { preHandler: requireAdmin }, async (request) => { const page = Math.max(1, Number(request.query?.page) || 1); const limit = safeLimit(request.query?.limit, 50, 100); const offset = (page - 1) * limit; const total = db.prepare("SELECT COUNT(*) AS count FROM reports").get().count; const rows = db.prepare("SELECT r.*,l.public_id FROM reports r LEFT JOIN license_keys l ON l.id=r.license_id ORDER BY r.id DESC LIMIT ? OFFSET ?").all(limit, offset); return { items: rows.map((row) => ({ id: row.id, licenseId: row.license_id, publicId: row.public_id, deviceId: row.device_id, payloadSize: row.payload_size, receivedAt: row.received_at })), page, limit, total }; });
  app.get("/api/admin/reports/:id", { preHandler: requireAdmin }, async (request, reply) => { const row = db.prepare("SELECT r.*,l.public_id FROM reports r LEFT JOIN license_keys l ON l.id=r.license_id WHERE r.id=?").get(Number(request.params.id)); if (!row) return reply.code(404).send({ error: "NOT_FOUND" }); return { id: row.id, publicId: row.public_id, deviceId: row.device_id, payload: decryptAtRest(masterSecret, row.payload_encrypted), payloadSize: row.payload_size, receivedAt: row.received_at }; });
  app.delete("/api/admin/reports/:id", { preHandler: requireOperatorMutation }, async (request, reply) => { const result = db.prepare("DELETE FROM reports WHERE id=?").run(Number(request.params.id)); if (!result.changes) return reply.code(404).send({ error: "NOT_FOUND" }); return { ok: true }; });
  app.post("/api/admin/reports/purge", { preHandler: requireOperatorMutation }, async (request) => { const before = validIso(request.body?.before) || nowIso(); const result = db.prepare("DELETE FROM reports WHERE received_at<?").run(before); return { deleted: result.changes }; });
  app.get("/api/admin/audit", { preHandler: requireAdmin }, async (request) => { const page = Math.max(1, Number(request.query?.page) || 1); const limit = safeLimit(request.query?.limit, 50, 100); const offset = (page - 1) * limit; const total = db.prepare("SELECT COUNT(*) AS count FROM audit_log").get().count; const rows = db.prepare("SELECT a.id,a.action,a.object_type,a.object_id,a.metadata,a.created_at,u.username FROM audit_log a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT ? OFFSET ?").all(limit, offset); return { items: rows.map((row) => ({ id: row.id, action: row.action, objectType: row.object_type, objectId: row.object_id, metadata: JSON.parse(row.metadata), username: row.username, createdAt: row.created_at })), page, limit, total }; });

  app.addHook("onClose", async () => { if (!options.db) db.close(); });
  return app;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  buildApp().then(async (app) => { await app.listen({ host: HOST, port: PORT }); app.log.info({ host: HOST, port: PORT, dashboardOrigin: DASHBOARD_ORIGIN }, "jur10n server started"); }).catch((error) => { console.error(error); process.exit(1); });
}
