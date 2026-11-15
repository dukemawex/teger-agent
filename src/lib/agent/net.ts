/** SSRF-safe network access for agent tools. Never runs on the user's device. */
import { lookup } from "node:dns/promises";
import net from "node:net";

export class BlockedTargetError extends Error {}

function ipv4ToInt(ip: string) {
  return ip.split(".").reduce((a, o) => (a << 8) + Number(o), 0) >>> 0;
}
const V4_BLOCKS: [string, number][] = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
  ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
];

export function isBlockedIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const n = ipv4ToInt(ip);
    return V4_BLOCKS.some(([base, bits]) => (n >>> (32 - bits)) === (ipv4ToInt(base) >>> (32 - bits)));
  }
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    if (l === "::" || l === "::1") return true;
    const mapped = l.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isBlockedIp(mapped[1]);
    // IPv4-mapped / IPv4-compatible in hex form, e.g. ::ffff:7f00:1 or ::7f00:1
    const hex = l.match(/^::(?:ffff:)?([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (hex) {
      const hi = parseInt(hex[1], 16), lo = parseInt(hex[2], 16);
      return isBlockedIp(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
    }
    return /^(fc|fd|fe8|fe9|fea|feb|ff|2001:db8|64:ff9b)/.test(l);
  }
  return true;
}

export async function assertPublicHost(host: string): Promise<void> {
  if (!host || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".internal") || host.endsWith(".local")) {
    throw new BlockedTargetError("Target host is not public.");
  }
  if (net.isIP(host)) {
    if (isBlockedIp(host)) throw new BlockedTargetError("Target IP is private or reserved.");
    return;
  }
  const addrs = await lookup(host, { all: true });
  if (!addrs.length || addrs.some((a) => isBlockedIp(a.address))) throw new BlockedTargetError("Target resolves to a private or reserved address.");
}

export interface SafeFetchResult {
  hops: { url: string; status: number }[];
  finalUrl: string;
  status: number;
  contentType?: string;
  body: string;
  truncated: boolean;
}

export interface Net {
  safeFetch(url: string, opts?: { maxHops?: number; maxBytes?: number; timeoutMs?: number; method?: string; headers?: Record<string, string>; body?: string }): Promise<SafeFetchResult>;
  fetchJson(url: string, init?: RequestInit, timeoutMs?: number): Promise<unknown>;
}

async function readLimited(res: Response, maxBytes: number): Promise<{ body: string; truncated: boolean }> {
  if (!res.body) return { body: "", truncated: false };
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      chunks.push(value.slice(0, value.byteLength - (total - maxBytes)));
      truncated = true;
      await reader.cancel();
      break;
    }
    chunks.push(value);
  }
  return { body: new TextDecoder().decode(Buffer.concat(chunks)), truncated };
}

export const realNet: Net = {
  async safeFetch(url, opts = {}) {
    const maxHops = opts.maxHops ?? 5;
    const maxBytes = opts.maxBytes ?? 200_000;
    const deadline = Date.now() + (opts.timeoutMs ?? 6000);
    const hops: { url: string; status: number }[] = [];
    let current = url;
    for (let i = 0; i <= maxHops; i++) {
      const u = new URL(current);
      if (!["http:", "https:"].includes(u.protocol)) throw new BlockedTargetError("Only http(s) is allowed.");
      if (u.port && !["80", "443"].includes(u.port)) throw new BlockedTargetError("Non-standard ports are not fetched.");
      if (u.username || u.password) throw new BlockedTargetError("URLs with credentials are not fetched.");
      await assertPublicHost(u.hostname.replace(/^\[|\]$/g, ""));
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new Error("Timed out");
      const res = await fetch(current, {
        method: opts.method ?? "GET",
        headers: { "user-agent": "TegerAgent/0.2 (+https://github.com/dukemawex/teger-agent; safety scanner)", accept: "text/html,*/*;q=0.5", ...(opts.headers ?? {}) },
        body: opts.body,
        redirect: "manual",
        signal: AbortSignal.timeout(remaining),
      });
      hops.push({ url: current, status: res.status });
      const loc = res.headers.get("location");
      if (res.status >= 300 && res.status < 400 && loc) {
        current = new URL(loc, current).href;
        await res.body?.cancel();
        continue;
      }
      const { body, truncated } = await readLimited(res, maxBytes);
      return { hops, finalUrl: current, status: res.status, contentType: res.headers.get("content-type") ?? undefined, body, truncated };
    }
    throw new Error(`Too many redirects (>${maxHops})`);
  },
  async fetchJson(url, init, timeoutMs = 6000) {
    const res = await fetch(url, { ...init, redirect: "follow", signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  },
};

/** Offline network used in tests and when TEGER_OFFLINE=1. */
export const offlineNet: Net = {
  async safeFetch() {
    throw new Error("offline");
  },
  async fetchJson() {
    throw new Error("offline");
  },
};
