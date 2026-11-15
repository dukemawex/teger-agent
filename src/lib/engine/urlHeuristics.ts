/** URL structure heuristics (ported from teger_security_core/detectors/url_heuristics.py). */
import { isOfficialDomain } from "./brands";
import { ParsedUrl } from "./urls";
import { FindingCollector } from "./types";

export const SUSPICIOUS_TLDS = new Set(["zip", "mov", "top", "xyz", "click", "tk", "ml", "ga", "cf", "gq", "work", "rest", "cam", "country", "support", "icu", "sbs", "cfd", "lat"]);
export const URL_SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id", "t.ly"]);
const REDIRECT_PARAMS = new Set(["url", "u", "redirect", "redirect_url", "redirect_uri", "redir", "next", "return", "returnurl", "return_to", "target", "dest", "destination", "continue", "goto", "out", "link"]);
const DECEPTIVE_HOST_TOKENS = ["login", "signin", "verify", "secure", "account", "update", "wallet", "support", "auth", "renew", "billing"];
const CREDENTIAL_PATH_TOKENS = ["login", "signin", "sign-in", "logon", "verify", "password", "account", "auth", "webscr"];

export function urlHeuristics(u: ParsedUrl, c: FindingCollector) {
  const host = u.host;
  if (u.isIpLiteral) {
    c.add({ category: "ip_literal_host", severity: "medium", tactic: "link_manipulation", description: "Link points to a raw IP address instead of a domain name.", indicator: host });
  }
  if (u.hasUserinfo) {
    c.add({ category: "userinfo_in_url", severity: "high", tactic: "link_manipulation", description: "Link hides its real destination behind an '@' (user-info) prefix.", indicator: u.href.slice(0, 80) });
  }
  if (u.unicodeHost && /[^\x00-\x7f]/.test(u.unicodeHost)) {
    const latin = /[a-z]/i.test(u.unicodeHost);
    const nonLatin = /[\u0370-\u03ff\u0400-\u04ff]/.test(u.unicodeHost);
    c.add(latin && nonLatin
      ? { category: "mixed_script_host", severity: "high", tactic: "link_manipulation", description: "Domain mixes alphabets (e.g. Latin and Cyrillic), a classic look-alike trick.", indicator: `${u.unicodeHost} (${host})` }
      : { category: "internationalized_host", severity: "low", tactic: "link_manipulation", description: "Domain uses internationalized (non-ASCII) characters.", indicator: `${u.unicodeHost} (${host})` });
  }
  const reg = u.registrableDomain;
  if (reg && URL_SHORTENERS.has(reg)) {
    c.add({ category: "url_shortener", severity: "low", tactic: "link_manipulation", description: "Link uses a URL shortener that hides the final destination.", indicator: host });
  }
  if (reg) {
    const tld = reg.split(".").pop()!;
    if (SUSPICIOUS_TLDS.has(tld)) c.add({ category: "high_abuse_tld", severity: "low", tactic: "link_manipulation", description: `Domain uses the '.${tld}' top-level domain, frequently abused.`, indicator: host });
    if (host.split(".").length >= 5) c.add({ category: "excessive_subdomains", severity: "low", tactic: "link_manipulation", description: "Domain has an unusually deep chain of subdomains.", indicator: host });
    const sub = host.slice(0, -reg.length);
    if (!isOfficialDomain(reg) && (DECEPTIVE_HOST_TOKENS.some((t) => sub.includes(t)) || (reg.includes("-") && DECEPTIVE_HOST_TOKENS.some((t) => reg.includes(t))))) {
      c.add({ category: "deceptive_host_keyword", severity: "low", tactic: "link_manipulation", description: "Domain contains security/login wording often used to look official.", indicator: host });
    }
  }
  if (u.port && ![80, 443].includes(u.port)) c.add({ category: "non_standard_port", severity: "low", tactic: "link_manipulation", description: `Link uses non-standard port ${u.port}.`, indicator: host });
  const params = new URLSearchParams(u.query);
  for (const [k, v] of params) {
    if (REDIRECT_PARAMS.has(k.toLowerCase()) && /^https?:|^\/\//i.test(decodeURIComponent(v))) {
      c.add({ category: "embedded_redirect", severity: "medium", tactic: "link_manipulation", description: "Link carries another URL in a redirect parameter.", indicator: `${host} → ${v.slice(0, 60)}` });
      break;
    }
  }
  if (u.scheme === "http" && CREDENTIAL_PATH_TOKENS.some((t) => u.path.toLowerCase().includes(t))) {
    c.add({ category: "credential_path_without_tls", severity: "medium", tactic: "credential_harvesting", description: "Login-style page served without HTTPS.", indicator: `${host}${u.path.slice(0, 40)}` });
  }
  if (u.href.length > 200) c.add({ category: "very_long_url", severity: "low", tactic: "link_manipulation", description: "Link is unusually long.", indicator: host, weight: 4 });
}
