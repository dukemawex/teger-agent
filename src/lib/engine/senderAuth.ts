/** Header-based sender authentication checks: SPF / DKIM / DMARC results and From vs Reply-To. */
import { registrableDomain, senderDomain } from "./urls";
import { FindingCollector } from "./types";

export interface SenderAuthResult {
  spf?: string;
  dkim?: string;
  dmarc?: string;
  from_domain?: string;
  reply_to_domain?: string;
  return_path_domain?: string;
  headers_present: boolean;
}

function headerValue(headers: string, name: string): string | undefined {
  const m = headers.match(new RegExp(`^${name}:\\s*(.+(?:\\n[ \\t].+)*)`, "im"));
  return m ? m[1].replace(/\n[ \t]+/g, " ").trim() : undefined;
}

export function checkSenderAuth(headers: string, sender: string, replyTo: string | undefined, c: FindingCollector): SenderAuthResult {
  const res: SenderAuthResult = { headers_present: !!headers.trim() };
  const authRes = headerValue(headers, "Authentication-Results") ?? "";
  for (const k of ["spf", "dkim", "dmarc"] as const) {
    const m = authRes.match(new RegExp(`\\b${k}=(\\w+)`, "i"));
    if (m) res[k] = m[1].toLowerCase();
  }
  const from = headerValue(headers, "From") ?? sender;
  const reply = headerValue(headers, "Reply-To") ?? replyTo;
  const rp = headerValue(headers, "Return-Path");
  res.from_domain = senderDomain(from);
  res.reply_to_domain = senderDomain(reply);
  res.return_path_domain = senderDomain(rp);

  if (res.dmarc === "fail") c.add({ category: "dmarc_fail", severity: "high", tactic: "authority_spoofing", description: "DMARC failed: the message is not authorized by the domain it claims to come from.", indicator: `dmarc=${res.dmarc}` });
  if (res.spf && ["fail", "softfail"].includes(res.spf)) c.add({ category: "spf_fail", severity: "medium", tactic: "authority_spoofing", description: `SPF ${res.spf}: the sending server is not authorized for this domain.`, indicator: `spf=${res.spf}` });
  if (res.dkim && ["fail", "none"].includes(res.dkim)) c.add({ category: "dkim_fail", severity: "low", tactic: "authority_spoofing", description: `DKIM ${res.dkim}: the message carries no valid domain signature.`, indicator: `dkim=${res.dkim}` });
  const fr = res.from_domain ? registrableDomain(res.from_domain) : undefined;
  const rr = res.reply_to_domain ? registrableDomain(res.reply_to_domain) : undefined;
  if (fr && rr && fr !== rr) {
    c.add({ category: "reply_to_mismatch", severity: "high", tactic: "authority_spoofing", description: `Replies go to ${res.reply_to_domain}, not the sender's domain ${res.from_domain}. Your answer would reach someone else.`, indicator: `From @${res.from_domain} / Reply-To @${res.reply_to_domain}` });
  }
  return res;
}
