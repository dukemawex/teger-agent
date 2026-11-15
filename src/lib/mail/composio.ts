/**
 * Gmail through Composio (https://docs.composio.dev). Composio hosts Google consent with its
 * managed OAuth app and keeps the tokens; Teger never sees them. Each Teger account is a Composio
 * user (user_id = Teger account id). Sessions are pinned to the gmail toolkit and to an explicit
 * allow-list of read / label / draft tools, so send, delete, trash and forward are unavailable
 * even if Teger had a bug.
 */
import type { MessageInput } from "../engine/engine";
import type { InboxMessage } from "./imap";
import { parseRawEmail } from "./parse";

export const GMAIL_TOOLKIT = "gmail";
/** Every Composio tool Teger may call. Nothing that sends, deletes, trashes, forwards or edits filters. */
export const ALLOWED_TOOLS = [
  "GMAIL_FETCH_EMAILS",
  "GMAIL_FETCH_MESSAGE_BY_MESSAGE_ID",
  "GMAIL_LIST_LABELS",
  "GMAIL_CREATE_LABEL",
  "GMAIL_ADD_LABEL_TO_EMAIL",
  "GMAIL_CREATE_EMAIL_DRAFT",
  "GMAIL_GET_PROFILE",
] as const;
export type AllowedTool = (typeof ALLOWED_TOOLS)[number];
export const NEW_MESSAGE_TRIGGER = "GMAIL_NEW_GMAIL_MESSAGE";

export interface ComposioAccount { id: string; status: string; toolkit: string }
export interface ComposioApi {
  createLink(userId: string, callbackUrl: string): Promise<{ redirectUrl: string; connectedAccountId?: string }>;
  listAccounts(userId: string): Promise<ComposioAccount[]>;
  deleteAccount(connectedAccountId: string): Promise<void>;
  execute(userId: string, connectedAccountId: string, tool: AllowedTool, args: Record<string, unknown>): Promise<Record<string, unknown>>;
  createTrigger(userId: string, connectedAccountId: string): Promise<string>;
  deleteTrigger(triggerId: string): Promise<void>;
  verifyWebhook(body: string, headers: Headers, secret: string): Promise<{ userId: string; triggerSlug: string; payload: Record<string, unknown> }>;
}

export const composioEnabled = () => !!process.env.COMPOSIO_API_KEY || !!testApi;

let testApi: ComposioApi | null = null;
export function setComposioForTests(api: ComposioApi | null) { testApi = api; }

let real: ComposioApi | null = null;
export async function composio(): Promise<ComposioApi> {
  if (testApi) return testApi;
  if (!process.env.COMPOSIO_API_KEY) throw new Error("composio_not_configured");
  if (real) return real;
  const { Composio } = await import("@composio/core");
  const c = new Composio({ apiKey: process.env.COMPOSIO_API_KEY });
  const session = (userId: string, connectedAccountId?: string, callbackUrl?: string) =>
    c.create(userId, {
      toolkits: [GMAIL_TOOLKIT],
      tools: { [GMAIL_TOOLKIT]: [...ALLOWED_TOOLS] },
      ...(connectedAccountId ? { connectedAccounts: { [GMAIL_TOOLKIT]: connectedAccountId } } : {}),
      ...(callbackUrl ? { manageConnections: { callbackUrl } } : {}),
    } as never);
  real = {
    async createLink(userId, callbackUrl) {
      const s = await session(userId, undefined, callbackUrl);
      const r = await s.authorize(GMAIL_TOOLKIT, { callbackUrl });
      if (!r.redirectUrl) throw new Error("Composio did not return a connect link");
      return { redirectUrl: r.redirectUrl, connectedAccountId: r.id };
    },
    async listAccounts(userId) {
      const r = await c.connectedAccounts.list({ userIds: [userId], toolkitSlugs: [GMAIL_TOOLKIT] });
      return r.items.map((a) => ({ id: a.id, status: String(a.status), toolkit: String((a.toolkit as { slug?: string })?.slug ?? GMAIL_TOOLKIT).toLowerCase() }));
    },
    async deleteAccount(id) { await c.connectedAccounts.delete(id); },
    async execute(userId, connectedAccountId, tool, args) {
      if (!(ALLOWED_TOOLS as readonly string[]).includes(tool)) throw new Error("tool_not_allowed");
      const s = await session(userId, connectedAccountId);
      const r = await s.execute(tool, args);
      if (r.resultType !== "completed") throw new Error(r.error || `${tool} ${r.resultType}`);
      return (r.data ?? {}) as Record<string, unknown>;
    },
    async createTrigger(userId, connectedAccountId) {
      const t = await c.triggers.create(userId, NEW_MESSAGE_TRIGGER, { connectedAccountId, triggerConfig: { labelIds: "INBOX" } } as never);
      return String((t as { triggerId?: string; id?: string }).triggerId ?? (t as { id?: string }).id);
    },
    async deleteTrigger(id) { await c.triggers.delete(id); },
    async verifyWebhook(body, headers, secret) {
      const r = await c.triggers.verifyWebhook({
        payload: body,
        id: headers.get("webhook-id") ?? "",
        timestamp: headers.get("webhook-timestamp") ?? "",
        signature: headers.get("webhook-signature") ?? "",
        secret,
      } as never);
      const p = r.payload as unknown as { userId?: string; triggerSlug?: string; payload?: Record<string, unknown> };
      return { userId: p.userId ?? "", triggerSlug: p.triggerSlug ?? "", payload: p.payload ?? {} };
    },
  };
  return real;
}

/* ---------- Gmail data normalisation (Composio returns Gmail API shapes) ---------- */

type Json = Record<string, unknown>;
const str = (v: unknown) => (typeof v === "string" ? v : "");
const dataOf = (d: Json): Json => (d && typeof d.data === "object" && d.data && !Array.isArray(d.data) && !("messageId" in d) ? (d.data as Json) : d);

export function toInboxList(d: Json): InboxMessage[] {
  const msgs = (dataOf(d).messages as Json[] | undefined) ?? [];
  return msgs.slice(0, 50).map((m) => {
    const preview = (m.preview as Json | undefined) ?? {};
    const text = str(preview.body) || str(m.messageText);
    return {
      ref: str(m.messageId) || str(m.id),
      from: str(m.sender),
      subject: str(m.subject) || "(no subject)",
      date: str(m.messageTimestamp) || undefined,
      snippet: text.replace(/\s+/g, " ").trim().slice(0, 300),
    };
  }).filter((m) => /^[A-Za-z0-9]{1,40}$/.test(m.ref));
}

const KEEP = ["from", "reply-to", "return-path", "to", "subject", "date", "authentication-results", "received-spf", "dkim-signature", "arc-authentication-results"];
const b64 = (s: string) => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");

function walk(part: Json | undefined, out: { html: string; text: string }) {
  if (!part) return;
  const mime = str(part.mimeType).toLowerCase();
  const data = str((part.body as Json | undefined)?.data);
  if (data && mime === "text/html" && !out.html) out.html = b64(data);
  else if (data && mime === "text/plain" && !out.text) out.text = b64(data);
  for (const p of (part.parts as Json[] | undefined) ?? []) walk(p, out);
}

/** Full Gmail message (Composio GMAIL_FETCH_MESSAGE_BY_MESSAGE_ID) -> the agent's MessageInput. */
export async function toMessageInput(d: Json): Promise<MessageInput> {
  const m = dataOf(d);
  const raw = str(m.raw) || str((m.payload as Json | undefined)?.raw);
  if (raw) return parseRawEmail(Buffer.from(raw.replace(/-/g, "+").replace(/_/g, "/"), "base64"));
  const payload = (m.payload as Json | undefined) ?? {};
  const headers = ((payload.headers as { name?: string; value?: string }[] | undefined) ?? []).filter((h) => h.name && typeof h.value === "string");
  const h = (n: string) => headers.find((x) => x.name!.toLowerCase() === n)?.value ?? "";
  const out = { html: "", text: "" };
  walk(payload, out);
  const body = (out.html && out.html.length < 60_000 ? out.html : out.text || str(m.messageText)).slice(0, 12_000);
  return {
    sender: h("from") || str(m.sender),
    reply_to: h("reply-to"),
    subject: h("subject") || str(m.subject),
    headers: headers.filter((x) => KEEP.includes(x.name!.toLowerCase())).map((x) => `${x.name}: ${x.value!.replace(/\s+/g, " ")}`.slice(0, 1200)).join("\n").slice(0, 4000),
    body,
  };
}

export function labelIdFrom(d: Json, name: string): string | null {
  const labels = (dataOf(d).labels as { id?: string; name?: string }[] | undefined) ?? [];
  return labels.find((l) => l.name === name)?.id ?? null;
}

/* ---------- High-level operations used by the inbox layer ---------- */

export async function listGmailViaComposio(userId: string, ca: string, max = 20): Promise<InboxMessage[]> {
  const api = await composio();
  return toInboxList(await api.execute(userId, ca, "GMAIL_FETCH_EMAILS", { user_id: "me", max_results: max, label_ids: ["INBOX"], include_payload: false, verbose: false }));
}

export async function fetchGmailViaComposio(userId: string, ca: string, messageId: string): Promise<MessageInput> {
  const api = await composio();
  return toMessageInput(await api.execute(userId, ca, "GMAIL_FETCH_MESSAGE_BY_MESSAGE_ID", { user_id: "me", message_id: messageId, format: "full" }));
}

export async function labelGmailViaComposio(userId: string, ca: string, messageId: string, label: "TEGER_DO_NOT_TRUST" | "TEGER_CAUTION"): Promise<string> {
  const api = await composio();
  let id = labelIdFrom(await api.execute(userId, ca, "GMAIL_LIST_LABELS", { user_id: "me" }), label);
  if (!id) {
    const created = dataOf(await api.execute(userId, ca, "GMAIL_CREATE_LABEL", { user_id: "me", label_name: label, label_list_visibility: "labelShow", message_list_visibility: "show" }));
    id = str(created.id);
    if (!id) throw new Error("label_create_failed");
  }
  await api.execute(userId, ca, "GMAIL_ADD_LABEL_TO_EMAIL", { user_id: "me", message_id: messageId, add_label_ids: [id] });
  return "gmail label (Composio)";
}

/** Saves a DRAFT only. Teger never sends: the user reviews, adds a known-good recipient, and sends it themselves. */
export async function verificationDraftViaComposio(userId: string, ca: string, subject: string, sender: string): Promise<void> {
  const api = await composio();
  const body = [
    "Hi,",
    "",
    `I received a message from ${sender || "someone claiming to be you"} with the subject "${subject.slice(0, 160)}" asking to change payment or bank details.`,
    "Before I act on it, can you confirm whether this request is genuine? I'm contacting you through details I already had on file rather than replying to that message.",
    "",
    "Thanks",
  ].join("\n");
  await api.execute(userId, ca, "GMAIL_CREATE_EMAIL_DRAFT", { user_id: "me", subject: `Verifying a payment-details request: ${subject.slice(0, 120)}`, body, is_html: false });
}

export async function profileEmailViaComposio(userId: string, ca: string): Promise<string> {
  try {
    const api = await composio();
    const d = dataOf(await api.execute(userId, ca, "GMAIL_GET_PROFILE", { user_id: "me" }));
    return str(d.emailAddress) || str((d.response_data as Json | undefined)?.emailAddress);
  } catch { return ""; }
}
