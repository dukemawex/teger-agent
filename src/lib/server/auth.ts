/** Accounts + signed session cookies (no third-party auth service required). */
import { cookies } from "next/headers";
import { getKV } from "./kv";
import { hashPassword, hmac, randomId, safeEqual, verifyPassword } from "./crypto";

export interface User {
  id: string;
  email: string;
  name: string;
  pw?: string;
  provider: "password" | "google";
  createdAt: string;
}
export type PublicUser = Omit<User, "pw">;

const COOKIE = "tgr_session";
const MAX_AGE = 60 * 60 * 24 * 30;

export const normEmail = (e: unknown) => (typeof e === "string" ? e.trim().toLowerCase() : "");
export const validEmail = (e: string) => /^[^\s@]{1,64}@[^\s@]{1,190}\.[a-z]{2,}$/i.test(e) && e.length <= 254;

export function publicUser(u: User): PublicUser {
  const { pw: _pw, ...rest } = u;
  return rest;
}

export async function createPasswordUser(email: string, password: string, name: string): Promise<User | "exists"> {
  const kv = getKV();
  const id = "u_" + randomId(12);
  if (!(await kv.setNx(`email:${email}`, id))) return "exists";
  const user: User = { id, email, name: name.slice(0, 80) || email.split("@")[0], pw: await hashPassword(password), provider: "password", createdAt: new Date().toISOString() };
  await kv.set(`user:${id}`, user);
  return user;
}

export async function findUserByEmail(email: string): Promise<User | null> {
  const kv = getKV();
  const id = await kv.get<string>(`email:${email}`);
  return id ? kv.get<User>(`user:${id}`) : null;
}

export async function loginPassword(email: string, password: string): Promise<User | null> {
  const u = await findUserByEmail(email);
  if (!u?.pw) {
    await verifyPassword(password, "scrypt$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); // equalize timing
    return null;
  }
  return (await verifyPassword(password, u.pw)) ? u : null;
}

export async function upsertGoogleUser(email: string, name: string): Promise<User> {
  const existing = await findUserByEmail(email);
  if (existing) return existing;
  const kv = getKV();
  const id = "u_" + randomId(12);
  const user: User = { id, email, name: name || email.split("@")[0], provider: "google", createdAt: new Date().toISOString() };
  if (!(await kv.setNx(`email:${email}`, id))) return (await findUserByEmail(email))!;
  await kv.set(`user:${id}`, user);
  return user;
}

export function sessionToken(userId: string): string {
  const payload = Buffer.from(JSON.stringify({ uid: userId, exp: Math.floor(Date.now() / 1000) + MAX_AGE })).toString("base64url");
  return `${payload}.${hmac(payload)}`;
}

export function readSessionToken(tok?: string): string | null {
  if (!tok) return null;
  const [payload, sig] = tok.split(".");
  if (!payload || !sig || !safeEqual(sig, hmac(payload))) return null;
  try {
    const { uid, exp } = JSON.parse(Buffer.from(payload, "base64url").toString());
    return typeof uid === "string" && exp > Date.now() / 1000 ? uid : null;
  } catch {
    return null;
  }
}

export async function setSession(userId: string) {
  (await cookies()).set(COOKIE, sessionToken(userId), { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax", path: "/", maxAge: MAX_AGE });
}

export async function clearSession() {
  (await cookies()).delete(COOKIE);
}

export async function currentUser(): Promise<User | null> {
  const uid = readSessionToken((await cookies()).get(COOKIE)?.value);
  return uid ? getKV().get<User>(`user:${uid}`) : null;
}

/** Same-origin check for state-changing requests (defense in depth on top of SameSite=Lax). */
export function sameOrigin(req: Request): boolean {
  const origin = req.headers.get("origin");
  if (!origin) return true; // non-browser clients (tests, curl) have no ambient cookies to abuse
  try {
    return new URL(origin).host === (req.headers.get("x-forwarded-host") ?? req.headers.get("host"));
  } catch {
    return false;
  }
}
