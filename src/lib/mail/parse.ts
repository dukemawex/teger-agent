/** Turn a raw RFC 822 email (.eml / IMAP source / Gmail raw) into the agent's MessageInput. */
import { simpleParser, AddressObject } from "mailparser";
import type { MessageInput } from "../engine/engine";

const KEEP_HEADERS = ["from", "reply-to", "return-path", "to", "subject", "date", "authentication-results", "received-spf", "dkim-signature", "arc-authentication-results"];

const addr = (a?: AddressObject | AddressObject[]) => {
  const first = Array.isArray(a) ? a[0] : a;
  const v = first?.value?.[0];
  if (!v?.address) return first?.text ?? "";
  return v.name ? `${v.name} <${v.address}>` : v.address;
};

export function looksLikeRawEmail(s: string): boolean {
  const head = s.slice(0, 4000);
  return /^(?:[A-Za-z-]+:.*\r?\n)+/m.test(head) && /^from:/im.test(head) && /^(subject|date|received|message-id|mime-version):/im.test(head);
}

export async function parseRawEmail(raw: string | Buffer): Promise<MessageInput & { date?: string }> {
  const m = await simpleParser(raw, { skipImageLinks: true, skipTextToHtml: true });
  const headerLines: string[] = [];
  for (const line of m.headerLines ?? []) {
    if (KEEP_HEADERS.includes(line.key)) headerLines.push(line.line.replace(/\r?\n[ \t]+/g, " ").slice(0, 1200));
  }
  // Keep raw HTML when present so hidden-text / prompt-injection detectors can see it.
  const html = typeof m.html === "string" ? m.html : "";
  const body = (html && html.length < 60_000 ? html : m.text || "").slice(0, 12_000);
  return {
    sender: addr(m.from),
    reply_to: addr(m.replyTo),
    subject: m.subject ?? "",
    headers: headerLines.join("\n").slice(0, 4000),
    body,
    date: m.date?.toISOString(),
  };
}
