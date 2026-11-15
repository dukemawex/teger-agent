/** Brand impersonation (ported from teger_security_core/detectors/brand.py). */
import { BRANDS, brandMentioned, isOfficialDomain } from "./brands";
import { displayName, ParsedUrl, registrableDomain, senderDomain } from "./urls";
import { FindingCollector } from "./types";

const CONFUSABLES: Record<string, string> = {
  "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a",
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
  "ԁ": "d", "ѕ": "s", "ɡ": "g", "ν": "v", "ο": "o", "α": "a", "ı": "i", "ӏ": "l", "ρ": "p", "κ": "k",
};
const MULTI: [string, string][] = [["rn", "m"], ["vv", "w"], ["cl", "d"]];

export function skeleton(label: string): string {
  let out = label.toLowerCase().normalize("NFKD").replace(/[\u0300-\u036f]/g, "");
  out = [...out].map((ch) => CONFUSABLES[ch] ?? ch).join("").replace(/-/g, "");
  for (const [s, d] of MULTI) out = out.split(s).join(d);
  return out;
}

export function editDistanceLe1(a: string, b: string): boolean {
  if (a === b) return true;
  if (Math.abs(a.length - b.length) > 1) return false;
  if (a.length === b.length) {
    const diffs: number[] = [];
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) diffs.push(i);
    return diffs.length === 1 || (diffs.length === 2 && diffs[1] === diffs[0] + 1 && a[diffs[0]] === b[diffs[1]] && a[diffs[1]] === b[diffs[0]]);
  }
  const [s, l] = a.length < b.length ? [a, b] : [b, a];
  for (let i = 0; i < l.length; i++) if (l.slice(0, i) + l.slice(i + 1) === s) return true;
  return false;
}

const tokenMatch = (kw: string, tokens: string[]) =>
  tokens.some((t) => t === kw || (kw.length >= 6 && (t.startsWith(kw) || t.endsWith(kw))));

/** Inspect a host (domain or URL) for brand look-alikes. */
export function inspectHost(host: string, path: string, c: FindingCollector, shownHost?: string) {
  const reg = registrableDomain(host) ?? host;
  if (isOfficialDomain(reg)) return;
  const shown = shownHost ?? host;
  const unicodeLabel = (shownHost ? registrableDomain(shownHost) ?? shownHost : reg).split(".")[0];
  const rawLabel = unicodeLabel.toLowerCase();
  const labelSk = skeleton(rawLabel);
  const hostTokens = shown.toLowerCase().split(/[.-]/).filter(Boolean).map(skeleton);
  const pathTokens = path.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  for (const b of BRANDS) {
    for (const kw of b.keywords) {
      if (rawLabel !== kw && labelSk === kw) {
        c.add({ category: "brand_homoglyph_domain", severity: "critical", tactic: "link_manipulation",
          description: `Domain imitates ${b.name} by substituting look-alike characters.`, indicator: shown !== host ? `${shown} (${host})` : shown });
      } else if (kw.length >= 6 && rawLabel !== kw && editDistanceLe1(labelSk, kw)) {
        c.add({ category: "brand_typosquat_domain", severity: "high", tactic: "link_manipulation",
          description: `Domain is one character away from ${b.name}'s name.`, indicator: shown });
      } else if (kw.length >= 4 && tokenMatch(kw, hostTokens)) {
        c.add({ category: "brand_name_on_untrusted_domain", severity: "high", tactic: "trust_transfer",
          description: `Domain uses the name '${kw}' but is not an official ${b.name} domain.`, indicator: shown });
      } else if (kw.length >= 4 && pathTokens.includes(kw)) {
        c.add({ category: "brand_name_in_path", severity: "medium", tactic: "trust_transfer",
          description: `Link path mentions ${b.name} on a domain ${b.name} does not use.`, indicator: `${host}${path.slice(0, 60)}` });
      }
    }
  }
}

export function brandDetector(urls: ParsedUrl[], sender: string, text: string, c: FindingCollector) {
  for (const u of urls) if (!u.isIpLiteral) inspectHost(u.host, u.path, c, u.unicodeHost ?? u.host);
  const display = displayName(sender);
  const sd = senderDomain(sender);
  const sreg = sd ? registrableDomain(sd) : undefined;
  const embedded = display.match(/[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/);
  if (embedded && sreg && registrableDomain(embedded[1].toLowerCase()) !== sreg) {
    c.add({ category: "display_name_address_mismatch", severity: "high", tactic: "authority_spoofing",
      description: "Sender display name shows a different email domain than the actual sending address.",
      indicator: `display shows @${embedded[1].toLowerCase()}, sent from @${sd}` });
  }
  for (const b of BRANDS) {
    if (sreg && display && brandMentioned(b, display) && !b.domains.includes(sreg)) {
      c.add({ category: "sender_brand_mismatch", severity: "high", tactic: "authority_spoofing",
        description: `Sender name claims to be ${b.name}, but the address is from ${sd}.`, indicator: `@${sd}` });
    }
    if (brandMentioned(b, text) && urls.length) {
      const off = urls.filter((u) => !u.isIpLiteral && !b.domains.includes(u.registrableDomain ?? ""));
      if (off.length && off.length === urls.length) {
        c.add({ category: "brand_link_mismatch", severity: "medium", tactic: "trust_transfer",
          description: `Message refers to ${b.name}, but none of its links go to an official ${b.name} domain.`, indicator: off[0].host });
      }
    }
  }
}
