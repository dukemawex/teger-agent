import { allow, clientIp } from "../ratelimit";
import { sameOrigin } from "./auth";

export const json = (data: unknown, status = 200) => Response.json(data, { status, headers: { "cache-control": "no-store" } });
/** Error body of every API route: a machine code (e.g. "bad_request", "busy") or a short user-facing sentence. */
export interface ApiError { error: string }
export const fail = (error: string, status = 400) => json({ error } satisfies ApiError, status);

export async function readJson(req: Request, max = 40_000): Promise<Record<string, unknown> | null> {
  const t = await req.text();
  if (t.length > max) return null;
  try { const v = JSON.parse(t); return v && typeof v === "object" ? v : null; } catch { return null; }
}

/** Origin check + per-IP rate limit for state-changing endpoints. */
export function guard(req: Request, bucket: string, limit = 20): Response | null {
  if (!sameOrigin(req)) return fail("forbidden", 403);
  if (!allow(`${bucket}:${clientIp(req)}`, limit)) return fail("busy", 429);
  return null;
}
