// 调试脚本：走已废弃的 v1 协议。生产服务器默认禁用 v1（未设 ENABLE_V1_PROTOCOL 时
// 一律 410 V1_PROTOCOL_DISABLED）。临时启用：在 /etc/jur10n/jur10n.env 加
// ENABLE_V1_PROTOCOL=1 并重启 jur10n-api。新的调试请改走 v2。
import { openDatabase } from "/srv/jur10n/api/src/db.js";
import { hmacHex, encryptClientPacket, decryptClientResponse, newNonce } from "/srv/jur10n/api/src/crypto.js";
const db = openDatabase(process.env.SQLITE_DATABASE_PATH);
const secret = Buffer.from(process.env.MASTER_SECRET, "base64url");
const code = process.env.CODE;
const digest = Buffer.from(hmacHex(secret, `license:${code}`), "hex");
const row = db.prepare("SELECT id, note, length(code_encrypted) AS n, typeof(code_encrypted) AS t, hex(code_encrypted) AS stored, status FROM license_keys WHERE note LIKE 'debug-%' ORDER BY id DESC LIMIT 1").get();
const match = db.prepare("SELECT COUNT(*) AS count FROM license_keys WHERE code_encrypted=?").get(digest);
const body = await encryptClientPacket(secret, { timestamp: Date.now(), nonce: newNonce(), op: "verify", code, device_id: "debug-device" });
// TODO(需要补充)：用 BASE_URL=https://你的API域名 指向你的服务器（默认是占位域名）
const response = await fetch(`${process.env.BASE_URL || "https://server.example.com"}/api/v1/client`, { method: "POST", headers: { "content-type": "application/octet-stream" }, body });
const result = await decryptClientResponse(secret, new Uint8Array(await response.arrayBuffer()));
console.log(JSON.stringify({ code, codeLength: code.length, secretBytes: secret.length, digest: digest.toString("hex"), row, match, result }, null, 2));
db.close();
