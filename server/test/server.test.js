import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

// Keep release files in a test-owned directory.  server.js reads FILES_ROOT at
// module load time, so it must be set before importing the application.
const filesRoot = mkdtempSync(join(tmpdir(), "jur10n-server-files-"));
process.env.FILES_ROOT = filesRoot;
// Exercise the explicit legacy window: production defaults ENABLE_V1_PROTOCOL off.
process.env.ENABLE_V1_PROTOCOL = "1";

const { buildApp } = await import("../src/server.js");
const { openDatabase, nowIso } = await import("../src/db.js");
const {
  decryptClientResponse,
  decryptSoftwarePacket,
  encryptAtRest,
  encryptClientPacket,
  encryptSoftwarePacket,
  generateSoftwareKey,
  hmacHex,
  newNonce,
  sha256,
  softwareKeyFingerprint,
} = await import("../src/crypto.js");

const masterSecret = Buffer.alloc(32, 7);

after(() => {
  rmSync(filesRoot, { recursive: true, force: true });
});

async function setup() {
  const dir = mkdtempSync(join(tmpdir(), "jur10n-server-"));
  const db = openDatabase(join(dir, "app.sqlite3"));
  const code = "JUR-TEST-9B3E8C7D";
  db.prepare("INSERT INTO license_keys(public_id,code_encrypted,status,expires_at,max_devices,note,created_at) VALUES(?,?,?,?,?,?,?)")
    .run("public-test", Buffer.from(hmacHex(masterSecret, `license:${code}`), "hex"), "active", null, 1, "test", nowIso());
  const app = await buildApp({ db, masterSecret, skipInitialAdmin: true, logger: false });
  await app.ready();
  return { app, db, dir, code };
}

async function clientCall(app, payload, ip = "198.51.100.20") {
  const body = await encryptClientPacket(masterSecret, {
    timestamp: Date.now(),
    nonce: newNonce(),
    ...payload,
  });
  const response = await app.inject({
    method: "POST",
    url: "/api/v1/client",
    headers: { "content-type": "application/octet-stream", "x-forwarded-for": ip },
    payload: body,
  });
  assert.equal(response.statusCode, 200);
  assert.equal(response.headers["content-type"], "application/octet-stream");
  return decryptClientResponse(masterSecret, response.rawPayload);
}

test("加密客户端接口支持验证、变量读取和上报", async () => {
  const { app, db, dir, code } = await setup();
  try {
    const verify = await clientCall(app, { op: "verify", code, device_id: "device-a" });
    assert.equal(verify.ok, true);
    assert.equal(verify.data.maxDevices, 1);

    db.prepare("INSERT INTO variables(var_key,value_encrypted,version,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?)")
      .run("feature.enabled", "", 1, 0, nowIso(), nowIso());
    const report = await clientCall(app, { op: "report", code, device_id: "device-a", data: { event: "boot" } });
    assert.equal(report.ok, true);
    assert.equal(report.data.accepted, true);

    const missingDevice = await clientCall(app, { op: "pull_variables", code, device_id: "device-b" });
    assert.equal(missingDevice.ok, false);
    assert.equal(missingDevice.error, "DEVICE_NOT_VERIFIED");
  } finally {
    await app.close();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("同一个加密包只能使用一次", async () => {
  const { app, db, dir, code } = await setup();
  try {
    const payload = { timestamp: Date.now(), nonce: newNonce(), op: "verify", code, device_id: "device-a" };
    const body = await encryptClientPacket(masterSecret, payload);
    const request = { method: "POST", url: "/api/v1/client", headers: { "content-type": "application/octet-stream" }, payload: body };
    const first = await app.inject(request);
    const second = await app.inject(request);
    assert.equal((await decryptClientResponse(masterSecret, first.rawPayload)).ok, true);
    const replay = await decryptClientResponse(masterSecret, second.rawPayload);
    assert.equal(replay.error, "REPLAY_DETECTED");
  } finally {
    await app.close();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});


function insertV2Software(db, slug, name, key, now) {
  const result = db.prepare(`INSERT INTO software_slots
    (slug,name,description,status,machine_check,ip_check,ip_change_policy,heartbeat_timeout,session_ttl,created_at,updated_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?)`).run(slug, name, `${name} integration test`, "active", 1, 0, "deny", 300, 604800, now, now);
  const id = Number(result.lastInsertRowid);
  db.prepare(`INSERT INTO software_keys
    (software_id,version,encrypted_key,fingerprint,status,not_before,created_at)
    VALUES(?,?,?,?,?,?,?)`).run(id, 1, encryptAtRest(masterSecret, key.toString("base64url")), softwareKeyFingerprint(key), "active", now, now);
  return { id, slug, key, version: 1 };
}

function insertV2License(db, softwareId, code, publicId, maxDevices = 2, now = nowIso()) {
  const result = db.prepare(`INSERT INTO license_codes
    (software_id,code_hash,public_id,status,expires_at,max_devices,note,created_at,updated_at)
    VALUES(?,?,?,?,?,?,?,?,?)`).run(softwareId, Buffer.from(hmacHex(masterSecret, `license:${code}`), "hex"), publicId, "active", null, maxDevices, "v2 integration", now, now);
  return Number(result.lastInsertRowid);
}

async function setupV2() {
  const dir = mkdtempSync(join(tmpdir(), "jur10n-v2-server-"));
  const db = openDatabase(join(dir, "app.sqlite3"));
  const now = nowIso();
  const software = insertV2Software(db, "v2-app", "V2 App", Buffer.alloc(32, 23), now);
  const otherSoftware = insertV2Software(db, "v2-other", "V2 Other", Buffer.alloc(32, 24), now);
  const code = "V2-TEST-CODE-PRIMARY";
  const otherCode = "V2-TEST-CODE-OTHER";
  insertV2License(db, software.id, code, "v2-public-primary", 2, now);
  insertV2License(db, otherSoftware.id, otherCode, "v2-public-other", 1, now);
  db.prepare(`INSERT INTO software_variables
    (software_id,var_key,value_encrypted,version,enabled,created_at,updated_at)
    VALUES(?,?,?,?,?,?,?)`).run(software.id, "shared.value", encryptAtRest(masterSecret, "from-v2-app"), 1, 1, now, now);
  db.prepare(`INSERT INTO software_variables
    (software_id,var_key,value_encrypted,version,enabled,created_at,updated_at)
    VALUES(?,?,?,?,?,?,?)`).run(otherSoftware.id, "shared.value", encryptAtRest(masterSecret, "from-v2-other"), 1, 1, now, now);
  const slotResult = db.prepare(`INSERT INTO data_slots
    (software_id,slug,name,description,enabled,single_limit,rolling_24h_limit,permanent_limit,max_records,retention_days,created_at,updated_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).run(software.id, "telemetry", "Telemetry", "v2 reports", 1, 0, 0, 0, 0, 90, now, now);
  const dataSlotId = Number(slotResult.lastInsertRowid);

  const fileContent = Buffer.from("jur10n-v2-file-content");
  const resourceDir = join(filesRoot, "resources", String(software.id));
  mkdirSync(resourceDir, { recursive: true });
  writeFileSync(join(resourceDir, "client.bin"), fileContent);
  const fileResult = db.prepare(`INSERT INTO software_resources
    (software_id,original_name,storage_name,storage_path,sha256,size,mime,status,created_at)
    VALUES(?,?,?,?,?,?,?,?,?)`).run(software.id, "client.bin", "client.bin", `resources/${software.id}/client.bin`, sha256(fileContent), fileContent.length, "application/octet-stream", "ready", now);

  const app = await buildApp({ db, masterSecret, skipInitialAdmin: true, logger: false });
  await app.ready();
  return {
    app,
    db,
    dir,
    software,
    otherSoftware,
    code,
    otherCode,
    dataSlotId,
    fileId: Number(fileResult.lastInsertRowid),
    fileContent,
  };
}

async function v2Call(app, software, clientKey, payload, ip = "198.51.100.20") {
  const body = encryptSoftwarePacket(clientKey.key, software.slug, clientKey.version, {
    protocol: "jur10n-client-v2",
    key_version: clientKey.version,
    timestamp: Date.now(),
    nonce: newNonce(),
    ...payload,
  }, "request");
  const response = await app.inject({
    method: "POST",
    url: `/api/v2/client/${software.slug}`,
    headers: { "content-type": "application/octet-stream", "x-forwarded-for": ip },
    payload: body,
  });
  assert.equal(response.statusCode, 200);
  assert.equal(response.headers["content-type"], "application/octet-stream");
  return decryptSoftwarePacket(clientKey.key, software.slug, clientKey.version, response.rawPayload, "response");
}

function sessionPayload(login, machineProof, op, extra = {}) {
  return { op, session_token: login.data.sessionToken, session_id: login.data.sessionId, machine_proof: machineProof, ...extra };
}

test("v2 登录、同机多会话、心跳、变量隔离、上报、manifest 和文件分片", async () => {
  const { app, db, dir, software, otherSoftware, code, dataSlotId, fileId, fileContent } = await setupV2();
  try {
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM software_slots WHERE slug IN ('v2-app','v2-other')").get().count, 2);
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM software_keys WHERE software_id=?").get(software.id).count, 1);

    const proof = "machine-proof-a-123456";
    const login = await v2Call(app, software, software, { op: "login", code, machine_proof: proof });
    assert.equal(login.ok, true);
    assert.equal(login.data.publicId, "v2-public-primary");
    assert.equal(typeof login.data.sessionToken, "string");
    assert.equal(typeof login.data.sessionId, "string");
    const session = (op, extra = {}) => sessionPayload(login, proof, op, extra);

    const secondSession = await v2Call(app, software, software, { op: "login", code, machine_proof: proof });
    assert.equal(secondSession.ok, true);
    assert.notEqual(secondSession.data.sessionId, login.data.sessionId);
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM client_sessions WHERE software_id=?").get(software.id).count, 2);

    const wrongMachine = await v2Call(app, software, software, sessionPayload(login, "machine-proof-b-123456", "heartbeat"));
    assert.equal(wrongMachine.ok, false);
    assert.equal(wrongMachine.error, "MACHINE_MISMATCH");

    const heartbeat = await v2Call(app, software, software, sessionPayload(login, proof, "heartbeat"));
    assert.equal(heartbeat.ok, true);
    assert.equal(typeof heartbeat.data.serverTime, "number");

    const variables = await v2Call(app, software, software, sessionPayload(login, proof, "pull_variables"));
    assert.equal(variables.ok, true);
    assert.deepEqual(variables.data.variables.map((item) => [item.key, item.value]), [["shared.value", "from-v2-app"]]);
    assert.equal(variables.data.variables.some((item) => item.value === "from-v2-other"), false);

    const generated = await v2Call(app, software, software, session("report", { data_slot: "telemetry", data: { event: "boot" } }));
    assert.equal(generated.ok, true);
    assert.equal(generated.data.mode, "created");
    const overwritten = await v2Call(app, software, software, session("report", { data_slot: "telemetry", mode: "overwrite", data: { event: "ready", count: 1 } }));
    assert.equal(overwritten.ok, true);
    assert.equal(overwritten.data.mode, "overwrite");
    const appended = await v2Call(app, software, software, session("report", { data_slot: "telemetry", mode: "append", data: { count: 2, extra: true } }));
    assert.equal(appended.ok, true);
    assert.equal(appended.data.mode, "append");
    const stored = db.prepare("SELECT value_encrypted,version FROM data_store WHERE software_id=? AND slot_id=? AND license_id=(SELECT id FROM license_codes WHERE software_id=? LIMIT 1)").get(software.id, dataSlotId, software.id);
    assert.equal(stored.version, 3);
    assert.deepEqual((await import("../src/crypto.js")).decryptAtRest(masterSecret, stored.value_encrypted), { event: "ready", count: 2, extra: true });

    const publicAnnouncement = await app.inject({ method: "GET", url: "/api/public/software/v2-app/announcement" });
    assert.equal(publicAnnouncement.statusCode, 200);
    assert.equal(publicAnnouncement.json().announcement, "");
    const announcement = await v2Call(app, software, software, { op: "announcement" });
    assert.equal(announcement.ok, true);
    assert.equal(announcement.data.announcement, "");

    const dataStoreRows = db.prepare("SELECT COUNT(*) AS count FROM data_store WHERE software_id=? AND slot_id=?").get(software.id, dataSlotId);
    assert.equal(dataStoreRows.count, 1);

    const manifest = await v2Call(app, software, software, sessionPayload(login, proof, "manifest"));
    assert.equal(manifest.ok, true);
    assert.equal(manifest.data.resources.length, 1);
    assert.equal(manifest.data.resources[0].id, fileId);
    assert.equal(manifest.data.resources[0].originalName, "client.bin");

    const chunk = await v2Call(app, software, software, sessionPayload(login, proof, "file_chunk", { file_id: fileId, offset: 0, length: fileContent.length }));
    assert.equal(chunk.ok, true);
    assert.equal(Buffer.from(chunk.data.chunk, "base64").toString(), fileContent.toString());
    assert.equal(chunk.data.eof, true);

    const missingFile = await v2Call(app, software, software, sessionPayload(login, proof, "file_chunk", { file_id: 999999, offset: 0, length: 1 }));
    assert.equal(missingFile.ok, false);
    assert.equal(missingFile.error, "FILE_NOT_FOUND");

    const noProof = await v2Call(app, software, software, { op: "login", code });
    assert.equal(noProof.ok, false);
    assert.equal(noProof.error, "MACHINE_PROOF_REQUIRED");

    const invalidOperation = await v2Call(app, software, software, sessionPayload(login, proof, "unknown"));
    assert.equal(invalidOperation.ok, false);
    assert.equal(invalidOperation.error, "INVALID_OPERATION");
    assert.equal(otherSoftware.slug, "v2-other");
  } finally {
    await app.close();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("v2 拒绝无效 timestamp 和 nonce 重放", async () => {
  const { app, db, dir, software, code } = await setupV2();
  try {
    const acceptedAtBoundary = await v2Call(app, software, software, {
      op: "login",
      code,
      machine_proof: "machine-proof-a-123456",
      timestamp: Date.now() - 59_000,
    });
    assert.equal(acceptedAtBoundary.ok, true);

    const invalidTimestamp = await v2Call(app, software, software, {
      op: "login",
      code,
      machine_proof: "machine-proof-a-123456",
      timestamp: Date.now() - 61_000,
    });
    assert.equal(invalidTimestamp.ok, false);
    assert.equal(invalidTimestamp.error, "TIMESTAMP_INVALID");

    const nonce = newNonce();
    const payload = {
      protocol: "jur10n-client-v2",
      key_version: software.version,
      timestamp: Date.now(),
      nonce,
      op: "login",
      code,
      machine_proof: "machine-proof-a-123456",
    };
    const body = encryptSoftwarePacket(software.key, software.slug, software.version, payload, "request");
    const request = { method: "POST", url: `/api/v2/client/${software.slug}`, headers: { "content-type": "application/octet-stream" }, payload: body };
    const first = await app.inject(request);
    const second = await app.inject(request);
    const firstResponse = decryptSoftwarePacket(software.key, software.slug, software.version, first.rawPayload, "response");
    const replayResponse = decryptSoftwarePacket(software.key, software.slug, software.version, second.rawPayload, "response");
    assert.equal(firstResponse.ok, true);
    assert.equal(replayResponse.ok, false);
    assert.equal(replayResponse.error, "REPLAY_DETECTED");
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM client_nonces WHERE software_id=? AND nonce=?").get(software.id, nonce).count, 1);
  } finally {
    await app.close();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("v2 report 遵守固定 200KB 累计配额并返回主要错误", async () => {
  const { app, db, dir, software, code } = await setupV2();
  try {
    const proof = "machine-proof-a-123456";
    const login = await v2Call(app, software, software, { op: "login", code, machine_proof: proof });
    assert.equal(login.ok, true);
    const session = (op, extra = {}) => sessionPayload(login, proof, op, extra);

    const accepted = await v2Call(app, software, software, session("report", { data_slot: "telemetry", data: { event: "ok" } }));
    assert.equal(accepted.ok, true);
    assert.equal(accepted.data.accepted, true);
    assert.equal(accepted.data.quotaBytes, 200 * 1024);

    const firstSnapshot = await v2Call(app, software, software, session("report", { data_slot: "telemetry", data: { first: "x".repeat(100 * 1024) } }));
    assert.equal(firstSnapshot.ok, true);
    assert.equal(firstSnapshot.data.mode, "overwrite");
    assert.equal(firstSnapshot.data.size > 100 * 1024, true);

    const overQuota = await v2Call(app, software, software, session("report", { data_slot: "telemetry", mode: "append", data: { second: "y".repeat(110 * 1024) } }));
    assert.equal(overQuota.ok, false);
    assert.equal(overQuota.error, "PAYLOAD_TOO_LARGE");

    const missingSlot = await v2Call(app, software, software, session("report", { data_slot: "missing", data: { event: "nope" } }));
    assert.equal(missingSlot.ok, false);
    assert.equal(missingSlot.error, "DATA_SLOT_NOT_FOUND");

    const badOffset = await v2Call(app, software, software, session("file_chunk", { file_id: 1, offset: -1, length: 1 }));
    assert.equal(badOffset.ok, false);
    assert.equal(badOffset.error, "INVALID_OFFSET");
  } finally {
    await app.close();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("管理路由存在性：集合、数据槽创建、删除、资源与批量操作均进入鉴权而非 404", async () => {
  const { app, db, dir } = await setupV2();
  try {
    const probes = [
      ["GET", "/api/admin/software"],
      ["GET", "/api/admin/software-slots"],
      ["POST", "/api/admin/software/v2-app/data-slots"],
      ["DELETE", "/api/admin/software/v2-app"],
      ["DELETE", "/api/admin/software/v2-app/data-slots/1"],
      ["GET", "/api/admin/software/v2-app/resources"],
      ["POST", "/api/admin/software/v2-app/resources"],
      ["DELETE", "/api/admin/software/v2-app/resources/1"],
      ["POST", "/api/admin/software/v2-app/licenses/batch"],
      ["GET", "/api/admin/monitoring"],
    ];
    for (const [method, url] of probes) {
      const response = await app.inject({ method, url });
      assert.notEqual(response.statusCode, 404, `${method} ${url} should not be a missing route`);
      assert.equal(response.statusCode, 401, `${method} ${url} should require admin auth`);
    }
  } finally {
    await app.close();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("软件槽位集合 canonical 路由和旧 alias 都进入管理员鉴权", async () => {
  const { app, db, dir } = await setupV2();
  try {
    const canonical = await app.inject({ method: "GET", url: "/api/admin/software" });
    const alias = await app.inject({ method: "GET", url: "/api/admin/software-slots" });
    assert.equal(canonical.statusCode, 401);
    assert.equal(alias.statusCode, 401);
    assert.notEqual(canonical.body, "Route GET:/api/admin/software not found");
    assert.notEqual(alias.body, "Route GET:/api/admin/software-slots not found");
  } finally {
    await app.close();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
