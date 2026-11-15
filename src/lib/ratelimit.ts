const g = globalThis as unknown as { __tegerRl?: Map<string, number[]> };
const hits: Map<string, number[]> = (g.__tegerRl ??= new Map());

/** Simple sliding-window limiter per key (per instance). Silent throttling by design. */
export function allow(key: string, limit = 12, windowMs = 60_000): boolean {
  const now = Date.now();
  const arr = (hits.get(key) ?? []).filter((t) => now - t < windowMs);
  if (arr.length >= limit) { hits.set(key, arr); return false; }
  arr.push(now);
  hits.set(key, arr);
  if (hits.size > 5000) hits.clear();
  return true;
}

export function clientIp(req: Request): string {
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || req.headers.get("x-real-ip") || "unknown";
}
