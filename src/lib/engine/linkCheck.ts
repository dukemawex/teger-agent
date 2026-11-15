/**
 * Link-only input: the user pasted one or more bare links (no email around them).
 * Normalizes bare domains to https:// URLs so every link tool can run on them, and
 * guesses which brand a look-alike host imitates so the agent can research it.
 */
import { BRANDS, Brand, isOfficialDomain } from "./brands";
import { editDistanceLe1, skeleton } from "./brand";
import type { MessageInput } from "./engine";
import { parseUrl, registrableDomain } from "./urls";

const MAX_LINKS = 5;
const SCHEME_URL = /^https?:\/\/\S+$/i;
const BARE_HOST = /^(?:www\.)?(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?\.)+\p{L}{2,24}(?::\d{1,5})?(?:[/?#]\S*)?$/u;

export interface LinkCheck {
  /** True when the input is only links: no sender, subject, headers or prose. */
  linkOnly: boolean;
  /** The message to analyze (bare domains rewritten as https:// URLs). */
  message: MessageInput;
  links: string[];
}

export function normalizeLinkCheck(m: MessageInput): LinkCheck {
  const body = (m.body ?? "").trim();
  const other = [m.sender, m.reply_to, m.subject, m.headers].some((v) => v?.trim());
  const tokens = body.split(/\s+/).filter(Boolean);
  if (other || !tokens.length || tokens.length > MAX_LINKS) return { linkOnly: false, message: m, links: [] };
  const links: string[] = [];
  for (const raw of tokens) {
    const t = raw.replace(/^[<("']+|[>)"'.,;]+$/g, "");
    if (SCHEME_URL.test(t)) links.push(t);
    else if (BARE_HOST.test(t) && !/^\d+(\.\d+)+$/.test(t)) links.push(`https://${t}`);
    else return { linkOnly: false, message: m, links: [] };
    if (!parseUrl(links[links.length - 1])) return { linkOnly: false, message: m, links: [] };
  }
  return { linkOnly: true, message: { ...m, body: links.join("\n") }, links };
}

/** The brand a host seems to imitate (look-alike letters, typos, or the brand name on another domain). */
export function brandHintForHost(host: string): Brand | undefined {
  const reg = registrableDomain(host) ?? host;
  if (isOfficialDomain(reg)) return undefined;
  const tokens = host.toLowerCase().split(/[.-]/).filter(Boolean).map(skeleton);
  const whole = skeleton(host.toLowerCase().replace(/\./g, ""));
  return BRANDS.find((b) => b.keywords.some((kw) => kw.length >= 4 && (tokens.some((t) => t === kw || (kw.length >= 6 && editDistanceLe1(t, kw))) || whole.includes(kw))));
}
