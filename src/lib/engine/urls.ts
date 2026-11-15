import { domainToUnicode } from "node:url";

const MULTI_PART_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "co.in", "co.za", "com.br", "com.ng", "org.ng", "gov.ng", "com.mx", "com.tr", "com.cn", "co.kr", "com.sg",
]);

export interface ParsedUrl {
  raw: string;
  href: string;
  scheme: string;
  host: string; // ascii/punycode
  unicodeHost?: string;
  registrableDomain?: string;
  path: string;
  query: string;
  port?: number;
  isIpLiteral: boolean;
  hasUserinfo: boolean;
}

export function registrableDomain(host: string): string | undefined {
  const h = host.toLowerCase().replace(/\.$/, "");
  if (!h || isIpLiteralHost(h)) return undefined;
  const parts = h.split(".");
  if (parts.length < 2) return undefined;
  const last2 = parts.slice(-2).join(".");
  if (MULTI_PART_SUFFIXES.has(last2) && parts.length >= 3) return parts.slice(-3).join(".");
  return last2;
}

export function isIpLiteralHost(h: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.startsWith("[") || /^0x[0-9a-f]+$/i.test(h) || /^\d{8,10}$/.test(h);
}

export function parseUrl(raw: string): ParsedUrl | undefined {
  let s = raw.trim().replace(/[)\].,;:!?'">]+$/, "");
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = "http://" + s;
  try {
    const u = new URL(s);
    if (!["http:", "https:"].includes(u.protocol)) return undefined;
    const host = u.hostname.toLowerCase();
    const uni = host.includes("xn--") ? domainToUnicode(host) : undefined;
    return {
      raw,
      href: u.href,
      scheme: u.protocol.replace(":", ""),
      host,
      unicodeHost: uni && uni !== host ? uni : undefined,
      registrableDomain: registrableDomain(host),
      path: u.pathname,
      query: u.search,
      port: u.port ? Number(u.port) : undefined,
      isIpLiteral: isIpLiteralHost(host),
      hasUserinfo: !!(u.username || u.password),
    };
  } catch {
    return undefined;
  }
}

const URL_RX = /\b(?:https?:\/\/|www\.)[^\s<>"'`]+/gi;

export function extractUrls(text: string, limit = 20): ParsedUrl[] {
  const out: ParsedUrl[] = [];
  const seen = new Set<string>();
  for (const m of text.matchAll(URL_RX)) {
    const p = parseUrl(m[0]);
    if (p && !seen.has(p.href)) {
      seen.add(p.href);
      out.push(p);
      if (out.length >= limit) break;
    }
  }
  return out;
}

export function senderDomain(sender?: string): string | undefined {
  if (!sender) return undefined;
  const m = sender.match(/<([^>]+)>/);
  const addr = (m ? m[1] : sender).trim();
  const at = addr.lastIndexOf("@");
  if (at < 0) return undefined;
  return addr.slice(at + 1).toLowerCase().replace(/[>\s]+$/, "");
}

export function displayName(sender?: string): string {
  if (!sender) return "";
  const m = sender.match(/^\s*"?([^"<]*)"?\s*</);
  return m ? m[1].trim() : "";
}
