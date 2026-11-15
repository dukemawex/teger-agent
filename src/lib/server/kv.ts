/**
 * Tiny key-value layer. Upstash Redis when configured (UPSTASH_REDIS_REST_URL/TOKEN or
 * KV_REST_API_URL/TOKEN), otherwise an in-process store for local dev and tests.
 * All keys are namespaced with "tgr:".
 */
import { Redis } from "@upstash/redis";

export interface KV {
  backend: "upstash-redis" | "in-memory";
  get<T>(key: string): Promise<T | null>;
  set(key: string, value: unknown, ttlSeconds?: number): Promise<void>;
  setNx(key: string, value: unknown): Promise<boolean>;
  del(key: string): Promise<void>;
  sadd(key: string, member: string): Promise<void>;
  srem(key: string, member: string): Promise<void>;
  smembers(key: string): Promise<string[]>;
  lpush(key: string, value: unknown, max: number): Promise<void>;
  lrange<T>(key: string, start: number, stop: number): Promise<T[]>;
  expire(key: string, seconds: number): Promise<void>;
}

const P = "tgr:";

class RedisKV implements KV {
  backend = "upstash-redis" as const;
  constructor(private r: Redis) {}
  async get<T>(k: string) { return (await this.r.get<T>(P + k)) ?? null; }
  async set(k: string, v: unknown, ttl?: number) { if (ttl) await this.r.set(P + k, v, { ex: ttl }); else await this.r.set(P + k, v); }
  async setNx(k: string, v: unknown) { return (await this.r.set(P + k, v, { nx: true })) === "OK"; }
  async del(k: string) { await this.r.del(P + k); }
  async sadd(k: string, m: string) { await this.r.sadd(P + k, m); }
  async srem(k: string, m: string) { await this.r.srem(P + k, m); }
  async smembers(k: string) { return (await this.r.smembers(P + k)) as string[]; }
  async lpush(k: string, v: unknown, max: number) { await this.r.lpush(P + k, v); await this.r.ltrim(P + k, 0, max - 1); }
  async lrange<T>(k: string, a: number, b: number) { return (await this.r.lrange<T>(P + k, a, b)) as T[]; }
  async expire(k: string, s: number) { await this.r.expire(P + k, s); }
}

type Entry = { v: unknown; exp?: number };
const g = globalThis as unknown as { __tgrKV?: Map<string, Entry> };

export class MemoryKV implements KV {
  backend = "in-memory" as const;
  m: Map<string, Entry> = (g.__tgrKV ??= new Map());
  private live(k: string) {
    const e = this.m.get(k);
    if (e?.exp && e.exp < Date.now()) { this.m.delete(k); return undefined; }
    return e;
  }
  async get<T>(k: string) { return (structuredClone(this.live(k)?.v) as T) ?? null; }
  async set(k: string, v: unknown, ttl?: number) { this.m.set(k, { v: structuredClone(v), exp: ttl ? Date.now() + ttl * 1000 : undefined }); }
  async setNx(k: string, v: unknown) { if (this.live(k)) return false; await this.set(k, v); return true; }
  async del(k: string) { this.m.delete(k); }
  async sadd(k: string, x: string) { const s = new Set((this.live(k)?.v as string[]) ?? []); s.add(x); this.m.set(k, { v: [...s], exp: this.live(k)?.exp }); }
  async srem(k: string, x: string) { const s = new Set((this.live(k)?.v as string[]) ?? []); s.delete(x); this.m.set(k, { v: [...s], exp: this.live(k)?.exp }); }
  async smembers(k: string) { return [...((this.live(k)?.v as string[]) ?? [])]; }
  async lpush(k: string, v: unknown, max: number) { const a = [structuredClone(v), ...((this.live(k)?.v as unknown[]) ?? [])].slice(0, max); this.m.set(k, { v: a, exp: this.live(k)?.exp }); }
  async lrange<T>(k: string, a: number, b: number) { const arr = (this.live(k)?.v as T[]) ?? []; return structuredClone(arr.slice(a, b < 0 ? undefined : b + 1)); }
  async expire(k: string, s: number) { const e = this.live(k); if (e) e.exp = Date.now() + s * 1000; }
}

let kv: KV | undefined;
export function getKV(): KV {
  if (kv) return kv;
  const url = process.env.UPSTASH_REDIS_REST_URL ?? process.env.KV_REST_API_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN ?? process.env.KV_REST_API_TOKEN;
  kv = url && token ? new RedisKV(new Redis({ url, token })) : new MemoryKV();
  return kv;
}
export function setKVForTests(k: KV) { kv = k; }
