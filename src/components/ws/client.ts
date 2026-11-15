"use client";
/** Browser helpers: guest identity header + NDJSON agent streaming. */
import type { AgentEvent } from "@/lib/agent/agent";

export function guestId(): string {
  let v = localStorage.getItem("teger_guest");
  if (!v) { v = "g_" + crypto.randomUUID().replace(/-/g, "").slice(0, 22); localStorage.setItem("teger_guest", v); }
  return v;
}

export async function api<T = Record<string, unknown>>(path: string, init: RequestInit = {}): Promise<{ ok: boolean; status: number; data: T }> {
  const r = await fetch(path, { ...init, headers: { "content-type": "application/json", "x-teger-guest": guestId(), ...(init.headers ?? {}) } });
  let data: T;
  try { data = await r.json(); } catch { data = {} as T; }
  return { ok: r.ok, status: r.status, data };
}

export type StreamEvent = AgentEvent | { type: "saved"; id: string };

export async function streamAgent(body: unknown, onEvent: (e: StreamEvent) => void): Promise<{ ok: boolean; status: number }> {
  const res = await fetch("/api/agent", { method: "POST", headers: { "content-type": "application/json", "x-teger-guest": guestId() }, body: JSON.stringify(body) });
  if (!res.ok || !res.body) return { ok: false, status: res.status };
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, i); buf = buf.slice(i + 1);
      if (line.trim()) onEvent(JSON.parse(line));
    }
  }
  return { ok: true, status: 200 };
}

export function looksLikeRawEmail(s: string): boolean {
  const head = s.slice(0, 4000);
  return /^from:/im.test(head) && /^(subject|date|received|message-id|mime-version):/im.test(head) && /^[A-Za-z-]+: /.test(head.trimStart());
}

export const VERDICT_LABEL: Record<string, string> = { malicious: "Malicious", suspicious: "Suspicious", unknown: "Unknown", no_threat_detected: "No threat detected" };
