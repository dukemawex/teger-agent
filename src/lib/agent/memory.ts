/** Per-identity learned allow/block lists, persisted in the KV store. */
import { getKV } from "../server/kv";

export interface UserLists {
  block: string[];
  allow: string[];
}

const GUEST_TTL = 60 * 60 * 24 * 7;

export async function getLists(identity: string): Promise<UserLists> {
  const kv = getKV();
  const [block, allow] = await Promise.all([kv.smembers(`block:${identity}`), kv.smembers(`allow:${identity}`)]);
  return { block, allow };
}

export async function addToList(identity: string, list: "block" | "allow", domain: string): Promise<UserLists> {
  const kv = getKV();
  const other = list === "block" ? "allow" : "block";
  await kv.srem(`${other}:${identity}`, domain);
  await kv.sadd(`${list}:${identity}`, domain);
  if (identity.startsWith("g_")) await kv.expire(`${list}:${identity}`, GUEST_TTL);
  return getLists(identity);
}

export async function removeFromLists(identity: string, domain: string): Promise<UserLists> {
  const kv = getKV();
  await kv.srem(`block:${identity}`, domain);
  await kv.srem(`allow:${identity}`, domain);
  return getLists(identity);
}

export function memoryBackend() {
  return getKV().backend;
}

export function sanitizeGuestId(id: unknown): string | null {
  return typeof id === "string" && /^g_[a-zA-Z0-9_-]{8,64}$/.test(id) ? id : null;
}

export function sanitizeDomain(d: unknown): string | undefined {
  if (typeof d !== "string") return undefined;
  const v = d.trim().toLowerCase();
  return /^[a-z0-9.-]{3,253}$/.test(v) && v.includes(".") ? v : undefined;
}
