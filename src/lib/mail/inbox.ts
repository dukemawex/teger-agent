/** Per-account inbox connection (Gmail via Composio, Gmail OAuth, or IMAP app password). Secrets stored encrypted; Composio keeps its own tokens. */
import { decrypt, encrypt } from "../server/crypto";
import { getKV } from "../server/kv";
import { accessFromRefresh, fetchGmailRaw, labelGmail, listGmail } from "./google";
import { fetchImapRaw, ImapConfig, InboxMessage, labelImap, listImap } from "./imap";
import { fetchGmailViaComposio, labelGmailViaComposio, listGmailViaComposio } from "./composio";
import { parseRawEmail } from "./parse";
import type { MessageInput } from "../engine/engine";

export type InboxConn =
  | { provider: "imap"; host: string; port: number; user: string; secret: string; connectedAt: string }
  | { provider: "gmail"; email: string; secret: string; connectedAt: string }
  | { provider: "composio"; email: string; connectedAccountId: string; connectedAt: string; triggerId?: string };

export async function getConn(userId: string): Promise<InboxConn | null> {
  return getKV().get<InboxConn>(`inbox:${userId}`);
}
export async function saveImap(userId: string, c: ImapConfig) {
  await getKV().set(`inbox:${userId}`, { provider: "imap", host: c.host, port: c.port, user: c.user, secret: encrypt(c.pass), connectedAt: new Date().toISOString() } satisfies InboxConn);
}
export async function saveGmail(userId: string, email: string, refreshToken: string) {
  await getKV().set(`inbox:${userId}`, { provider: "gmail", email, secret: encrypt(refreshToken), connectedAt: new Date().toISOString() } satisfies InboxConn);
}
export async function saveComposio(userId: string, connectedAccountId: string, email: string) {
  await getKV().set(`inbox:${userId}`, { provider: "composio", email, connectedAccountId, connectedAt: new Date().toISOString() } satisfies InboxConn);
}
export async function setComposioTrigger(userId: string, triggerId: string | undefined) {
  const c = await getConn(userId);
  if (c?.provider !== "composio") return;
  await getKV().set(`inbox:${userId}`, { ...c, triggerId });
}
export async function disconnect(userId: string) {
  await getKV().del(`inbox:${userId}`);
}
export function describe(c: InboxConn | null) {
  if (!c) return null;
  if (c.provider === "imap") return { provider: "imap", account: c.user, host: c.host, connectedAt: c.connectedAt };
  if (c.provider === "composio") return { provider: "composio", account: c.email || "Gmail account", connectedAt: c.connectedAt, autoScan: !!c.triggerId };
  return { provider: "gmail", account: c.email, connectedAt: c.connectedAt };
}

const imapCfg = (c: Extract<InboxConn, { provider: "imap" }>): ImapConfig => ({ host: c.host, port: c.port, user: c.user, pass: decrypt(c.secret) });

export async function listInbox(c: InboxConn, userId: string): Promise<InboxMessage[]> {
  if (c.provider === "imap") return listImap(imapCfg(c));
  if (c.provider === "composio") return listGmailViaComposio(userId, c.connectedAccountId);
  return listGmail(await accessFromRefresh(decrypt(c.secret)));
}
export async function fetchMessage(c: InboxConn, userId: string, ref: string): Promise<MessageInput> {
  if (c.provider === "composio") return fetchGmailViaComposio(userId, c.connectedAccountId, ref);
  if (c.provider === "imap") return parseRawEmail(await fetchImapRaw(imapCfg(c), ref));
  return parseRawEmail(await fetchGmailRaw(await accessFromRefresh(decrypt(c.secret)), ref));
}
export async function applyLabel(c: InboxConn, userId: string, ref: string, label: "TEGER_DO_NOT_TRUST" | "TEGER_CAUTION") {
  if (c.provider === "imap") return labelImap(imapCfg(c), ref, label);
  if (c.provider === "composio") return labelGmailViaComposio(userId, c.connectedAccountId, ref, label);
  return labelGmail(await accessFromRefresh(decrypt(c.secret)), ref, label);
}
