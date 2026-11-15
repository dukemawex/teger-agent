import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, scrypt as _scrypt, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(_scrypt) as (pw: string, salt: Buffer, len: number) => Promise<Buffer>;

export function secret(): string {
  const s = process.env.AUTH_SECRET;
  if (s && s.length >= 32) return s;
  if (process.env.NODE_ENV === "production" && process.env.VERCEL) throw new Error("AUTH_SECRET is not configured");
  return "dev-only-insecure-secret-change-me-0123456789abcdef";
}

export const b64u = (b: Buffer) => b.toString("base64url");

export function hmac(data: string, purpose = "session"): string {
  return b64u(createHmac("sha256", secret() + ":" + purpose).update(data).digest());
}

export function safeEqual(a: string, b: string) {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

export async function hashPassword(pw: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await scrypt(pw, salt, 32);
  return `scrypt$${b64u(salt)}$${b64u(key)}`;
}

export async function verifyPassword(pw: string, stored: string): Promise<boolean> {
  const [alg, s, k] = stored.split("$");
  if (alg !== "scrypt" || !s || !k) return false;
  const key = await scrypt(pw, Buffer.from(s, "base64url"), 32);
  return safeEqual(b64u(key), k);
}

function encKey(purpose: string) {
  return createHash("sha256").update(secret() + ":enc:" + purpose).digest();
}

/** AES-256-GCM for stored mailbox credentials / OAuth refresh tokens. */
export function encrypt(plain: string, purpose = "mail"): string {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", encKey(purpose), iv);
  const ct = Buffer.concat([c.update(plain, "utf8"), c.final()]);
  return `v1.${b64u(iv)}.${b64u(c.getAuthTag())}.${b64u(ct)}`;
}

export function decrypt(blob: string, purpose = "mail"): string {
  const [v, iv, tag, ct] = blob.split(".");
  if (v !== "v1") throw new Error("bad blob");
  const d = createDecipheriv("aes-256-gcm", encKey(purpose), Buffer.from(iv, "base64url"));
  d.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([d.update(Buffer.from(ct, "base64url")), d.final()]).toString("utf8");
}

export const randomId = (n = 16) => b64u(randomBytes(n));
