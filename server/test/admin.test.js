import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const filesRoot = mkdtempSync(join(tmpdir(), "jur10n-admin-files-"));
process.env.FILES_ROOT = filesRoot;
const homeDir = mkdtempSync(join(tmpdir(), "jur10n-admin-home-"));
process.env.INITIAL_ADMIN_PASSWORD_FILE = join(homeDir, "initial-admin-password");

const { buildApp } = await import("../src/server.js");

test("管理员全流程：登录、变量、数据槽、卡密、批量、资源与软件删除", async () => {
  const dir = mkdtempSync(join(tmpdir(), "jur10n-admin-"));
  const db = (await import("../src/db.js")).openDatabase(join(dir, "app.sqlite3"));
  const app = await buildApp({ db, masterSecret: Buffer.alloc(32, 9), logger: false });
  try {
    await app.ready();
    const initialPassword = readFileSync(process.env.INITIAL_ADMIN_PASSWORD_FILE, "utf8").trim();

    // Login and clear first-login password change requirement.
    const login = await app.inject({ method: "POST", url: "/api/admin/login", payload: { username: "owner", password: initialPassword } });
    assert.equal(login.statusCode, 200);
    const cookies = login.cookies;
    const csrf = login.json().csrfToken;
    const headers = { "x-csrf-token": csrf, cookie: cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join("; ") };
    const changed = await app.inject({ method: "POST", url: "/api/admin/password", headers, payload: { password: "owner-password-2026-secure" } });
    assert.equal(changed.statusCode, 200);

    // Create a software slot; key auto-provisioned.
    const created = await app.inject({ method: "POST", url: "/api/admin/software", headers, payload: { slug: "demo-app", name: "Demo App", description: "admin flow" } });
    assert.equal(created.statusCode, 200);
    assert.equal(created.json().software.slug, "demo-app");
    assert.ok(created.json().software.keyFingerprint);

    // Variables: create, list, update, delete.
    const variable = await app.inject({ method: "POST", url: "/api/admin/software/demo-app/variables", headers, payload: { key: "API_TIMEOUT", value: "30000", enabled: true } });
    assert.equal(variable.statusCode, 200);
    const variables = await app.inject({ method: "GET", url: "/api/admin/software/demo-app/variables", headers });
    assert.equal(variables.json().items.length, 1);
    assert.equal(variables.json().items[0].value, "30000");
    const variableId = variables.json().items[0].id;

    // Data slot create (the previously missing route), usage and delete.
    const slot = await app.inject({ method: "POST", url: "/api/admin/software/demo-app/data-slots", headers, payload: { slug: "events", name: "Events", enabled: true } });
    assert.equal(slot.statusCode, 200);
    assert.equal(slot.json().quotaBytes, 200 * 1024);
    const usage = await app.inject({ method: "GET", url: "/api/admin/software/demo-app/data-slots/usage", headers });
    assert.equal(usage.statusCode, 200);
    assert.equal(usage.json().items[0].quotaBytes, 200 * 1024);

    // Licenses: manual add with duplicate detection, then generate.
    const manual = await app.inject({ method: "POST", url: "/api/admin/software/demo-app/licenses", headers, payload: { codes: ["MY-CUSTOM-001", "MY-CUSTOM-001"] } });
    assert.equal(manual.statusCode, 200);
    assert.deepEqual(manual.json().codes, ["MY-CUSTOM-001"]);
    assert.equal(manual.json().duplicates.length, 1);
    const generated = await app.inject({ method: "POST", url: "/api/admin/software/demo-app/licenses", headers, payload: { count: 3, prefix: "DM" } });
    assert.equal(generated.json().codes.length, 3);
    const licenses = await app.inject({ method: "GET", url: "/api/admin/software/demo-app/licenses?search=MY-CUSTOM", headers });
    assert.equal(licenses.json().items.length, 1);
    const licenseId = licenses.json().items[0].id;

    // Batch operations.
    const banned = await app.inject({ method: "POST", url: "/api/admin/software/demo-app/licenses/batch", headers, payload: { action: "ban", ids: [licenseId] } });
    assert.equal(banned.json().changed, 1);
    const afterBan = await app.inject({ method: "GET", url: "/api/admin/software/demo-app/licenses?status=revoked", headers });
    assert.equal(afterBan.json().items.length, 1);
    const activated = await app.inject({ method: "POST", url: "/api/admin/software/demo-app/licenses/batch", headers, payload: { action: "activate", ids: [licenseId] } });
    assert.equal(activated.json().changed, 1);

    // Resources: upload, list, delete.
    const content = Buffer.from("admin-flow-resource");
    const uploaded = await app.inject({
      method: "POST", url: "/api/admin/software/demo-app/resources", headers,
      payload: { originalName: "patch.dat", content: content.toString("base64"), mime: "application/octet-stream" },
    });
    assert.equal(uploaded.statusCode, 200);
    const resourceId = uploaded.json().resource.id;
    assert.equal(uploaded.json().resource.sha256, (await import("../src/crypto.js")).sha256(content));
    const resources = await app.inject({ method: "GET", url: "/api/admin/software/demo-app/resources", headers });
    assert.equal(resources.json().items.length, 1);
    const removedResource = await app.inject({ method: "DELETE", url: `/api/admin/software/demo-app/resources/${resourceId}`, headers });
    assert.equal(removedResource.statusCode, 200);

    // Global monitoring endpoint.
    const monitoring = await app.inject({ method: "GET", url: "/api/admin/monitoring", headers });
    assert.equal(monitoring.statusCode, 200);
    assert.ok(monitoring.json().totals);

    // Variable cleanup and software hard delete with cascade.
    await app.inject({ method: "DELETE", url: `/api/admin/software/demo-app/variables/${variableId}`, headers });
    const removed = await app.inject({ method: "DELETE", url: "/api/admin/software/demo-app", headers });
    assert.equal(removed.statusCode, 200);
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM software_slots WHERE slug='demo-app'").get().count, 0);
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM license_codes WHERE software_id=(SELECT id FROM software_slots WHERE slug='demo-app')").get().count, 0);
  } finally {
    await app.close();
    db.close();
    rmSync(dir, { recursive: true, force: true });
    rmSync(filesRoot, { recursive: true, force: true });
    rmSync(homeDir, { recursive: true, force: true });
  }
});
