import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const AES_TAG_BYTES = 16;
export const MAX_PACKET_BYTES = 256 * 1024;
export const REQUEST_AAD = encoder.encode("jur10n:server:v1:request");
export const RESPONSE_AAD = encoder.encode("jur10n:server:v1:response");
const AT_REST_AAD = Buffer.from("jur10n:server:v1:at-rest");

export function b64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

export function unb64url(value) {
  return Buffer.from(String(value || ""), "base64url");
}

export function parseMasterSecret(value) {
  const raw = Buffer.isBuffer(value) ? Buffer.from(value) : unb64url(value);
  if (raw.length !== 32) throw new Error("MASTER_SECRET must be a 256-bit base64url value");
  return raw;
}

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function hmacHex(secret, value) {
  return createHmac("sha256", secret).update(String(value)).digest("hex");
}

export function hmacBuffer(secret, value) {
  return createHmac("sha256", secret).update(String(value)).digest();
}

export function randomToken(bytes = 32) {
  return b64url(randomBytes(bytes));
}

export function newNonce() {
  return randomUUID().replaceAll("-", "");
}

export function deriveClientKey(masterSecret) {
  return hmacBuffer(masterSecret, "client-v1");
}

export function generateSoftwareKey() {
  return randomBytes(32);
}

export function softwareKeyFingerprint(rawKey) {
  return sha256(rawKey);
}

export function requestAad(softwareSlot, keyVersion) {
  return encoder.encode(`jur10n:client:v2:${softwareSlot}:${keyVersion}:request`);
}

export function responseAad(softwareSlot, keyVersion) {
  return encoder.encode(`jur10n:client:v2:${softwareSlot}:${keyVersion}:response`);
}

function assertAesKey(rawKey) {
  const key = Buffer.from(rawKey || "");
  if (key.length !== 32) throw new Error("INVALID_KEY");
  return key;
}

function cryptSync(rawKey, payload, aad, decrypt = false) {
  const key = assertAesKey(rawKey);
  if (decrypt) {
    const bytes = Buffer.from(payload || "");
    if (bytes.length < 12 + AES_TAG_BYTES || bytes.length > MAX_PACKET_BYTES) throw new Error("INVALID_PACKET");
    const iv = bytes.subarray(0, 12);
    const encrypted = bytes.subarray(12, bytes.length - AES_TAG_BYTES);
    const tag = bytes.subarray(bytes.length - AES_TAG_BYTES);
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAAD(Buffer.from(aad));
    decipher.setAuthTag(tag);
    return JSON.parse(Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8"));
  }
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(aad));
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(payload), "utf8"), cipher.final()]);
  return Buffer.concat([iv, encrypted, cipher.getAuthTag()]);
}

export function encryptClientPacket(masterSecret, payload) {
  return cryptSync(masterSecret, payload, REQUEST_AAD, false);
}

export function decryptClientPacket(masterSecret, packed) {
  return cryptSync(masterSecret, packed, REQUEST_AAD, true);
}

export function encryptClientResponse(masterSecret, payload) {
  return cryptSync(masterSecret, payload, RESPONSE_AAD, false);
}

export function decryptClientResponse(masterSecret, packed) {
  return cryptSync(masterSecret, packed, RESPONSE_AAD, true);
}

export function encryptSoftwarePacket(rawKey, softwareSlot, keyVersion, payload, direction = "response") {
  const aad = direction === "request" ? requestAad(softwareSlot, keyVersion) : responseAad(softwareSlot, keyVersion);
  return cryptSync(rawKey, payload, aad, false);
}

export function decryptSoftwarePacket(rawKey, softwareSlot, keyVersion, packed, direction = "request") {
  const aad = direction === "request" ? requestAad(softwareSlot, keyVersion) : responseAad(softwareSlot, keyVersion);
  return cryptSync(rawKey, packed, aad, true);
}

function atRestKey(masterSecret) {
  return hmacBuffer(masterSecret, "at-rest-v1");
}

export function encryptAtRest(masterSecret, value) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", atRestKey(masterSecret), iv);
  cipher.setAAD(AT_REST_AAD);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
  return b64url(Buffer.concat([iv, cipher.getAuthTag(), encrypted]));
}

export function decryptAtRest(masterSecret, packed) {
  const bytes = unb64url(packed);
  if (bytes.length < 12 + AES_TAG_BYTES) throw new Error("INVALID_AT_REST_VALUE");
  const iv = bytes.subarray(0, 12);
  const tag = bytes.subarray(12, 12 + AES_TAG_BYTES);
  const encrypted = bytes.subarray(12 + AES_TAG_BYTES);
  const decipher = createDecipheriv("aes-256-gcm", atRestKey(masterSecret), iv);
  decipher.setAAD(AT_REST_AAD);
  decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8"));
}

export function timingSafeEqualText(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}

export { AES_TAG_BYTES };
