/**
 * IMAP inbox connector (read-only + optional label/keyword). Works with any provider that
 * supports app passwords: Gmail, Outlook.com, Yahoo, iCloud, Fastmail, Zoho…
 * Never sends, moves or deletes mail.
 */
import { ImapFlow } from "imapflow";
import { assertPublicHost } from "../agent/net";

export interface ImapConfig {
  host: string;
  port: number;
  user: string;
  pass: string;
}

export interface InboxMessage {
  ref: string;
  from: string;
  subject: string;
  date?: string;
  snippet?: string;
}

export const IMAP_PRESETS: Record<string, { host: string; port: number; help: string }> = {
  gmail: { host: "imap.gmail.com", port: 993, help: "Google Account → Security → 2-Step Verification → App passwords" },
  outlook: { host: "outlook.office365.com", port: 993, help: "Microsoft account → Security → Advanced security options → App passwords" },
  yahoo: { host: "imap.mail.yahoo.com", port: 993, help: "Yahoo Account Security → Generate app password" },
  icloud: { host: "imap.mail.me.com", port: 993, help: "appleid.apple.com → Sign-In and Security → App-Specific Passwords" },
  fastmail: { host: "imap.fastmail.com", port: 993, help: "Fastmail Settings → Privacy & Security → App passwords" },
  zoho: { host: "imap.zoho.com", port: 993, help: "Zoho Accounts → Security → App passwords" },
};

export function validateImapConfig(c: Partial<ImapConfig>): ImapConfig | string {
  const host = String(c.host ?? "").trim().toLowerCase();
  const port = Number(c.port ?? 993);
  const user = String(c.user ?? "").trim();
  const pass = String(c.pass ?? "").replace(/\s+/g, "");
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(host)) return "Enter a valid IMAP server name.";
  if (![993, 143].includes(port)) return "Port must be 993 (TLS) or 143 (STARTTLS).";
  if (!user || user.length > 254) return "Enter your email address / username.";
  if (!pass || pass.length > 256) return "Enter an app password.";
  return { host, port, user, pass };
}

async function withClient<T>(c: ImapConfig, fn: (client: ImapFlow) => Promise<T>): Promise<T> {
  // Never let a user point the server at internal hosts. (Test-only escape hatch for a local IMAP server.)
  if (!(process.env.NODE_ENV === "test" && process.env.TEGER_IMAP_ALLOW_PRIVATE === "1")) await assertPublicHost(c.host);
  const client = new ImapFlow({
    host: c.host, port: c.port, secure: c.port === 993, auth: { user: c.user, pass: c.pass },
    logger: false, socketTimeout: 20_000, greetingTimeout: 10_000, connectionTimeout: 10_000, emitLogs: false,
  });
  await client.connect();
  try {
    return await fn(client);
  } finally {
    await client.logout().catch(() => client.close());
  }
}

export async function testImap(c: ImapConfig): Promise<{ ok: true; mailbox: string; messages: number }> {
  return withClient(c, async (client) => {
    const st = await client.status("INBOX", { messages: true });
    return { ok: true, mailbox: "INBOX", messages: (st && st.messages) || 0 };
  });
}

export async function listImap(c: ImapConfig, limit = 20): Promise<InboxMessage[]> {
  return withClient(c, async (client) => {
    const lock = await client.getMailboxLock("INBOX", { readOnly: true });
    try {
      const total = typeof client.mailbox === "object" ? client.mailbox.exists : 0;
      if (!total) return [];
      const out: InboxMessage[] = [];
      for await (const msg of client.fetch(`${Math.max(1, total - limit + 1)}:*`, { uid: true, envelope: true })) {
        const f = msg.envelope?.from?.[0];
        out.push({ ref: String(msg.uid), from: f ? (f.name ? `${f.name} <${f.address}>` : f.address ?? "") : "", subject: msg.envelope?.subject ?? "(no subject)", date: msg.envelope?.date ? new Date(msg.envelope.date).toISOString() : undefined });
      }
      return out.reverse();
    } finally {
      lock.release();
    }
  });
}

export async function fetchImapRaw(c: ImapConfig, uid: string): Promise<Buffer> {
  if (!/^\d{1,10}$/.test(uid)) throw new Error("bad uid");
  return withClient(c, async (client) => {
    const lock = await client.getMailboxLock("INBOX", { readOnly: true });
    try {
      const msg = await client.fetchOne(uid, { source: true }, { uid: true });
      if (!msg || !msg.source) throw new Error("not found");
      return msg.source.subarray(0, 2_000_000);
    } finally {
      lock.release();
    }
  });
}

/** Apply a TEGER_* label (Gmail X-GM-LABELS) or IMAP keyword. Never moves or deletes. */
export async function labelImap(c: ImapConfig, uid: string, label: "TEGER_DO_NOT_TRUST" | "TEGER_CAUTION"): Promise<string> {
  if (!/^\d{1,10}$/.test(uid)) throw new Error("bad uid");
  return withClient(c, async (client) => {
    const lock = await client.getMailboxLock("INBOX");
    try {
      const gmail = client.capabilities.has("X-GM-EXT-1");
      await client.messageFlagsAdd(uid, [label], { uid: true, useLabels: gmail });
      return gmail ? "gmail-label" : "imap-keyword";
    } finally {
      lock.release();
    }
  });
}
