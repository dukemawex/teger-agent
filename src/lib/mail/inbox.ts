/** Per-account inbox connection (IMAP app password or Gmail OAuth), stored encrypted. */
import { decrypt, encrypt } from "../server/crypto";
import { getKV } from "../server/kv";
import { accessFromRefresh, fetchGmailRaw, labelGmail, listGmail } from "./google";
import { fetchImapRaw, ImapConfig, InboxMessage, labelImap, listImap } from "./imap";

export type InboxConn =
  | { provider: "imap"; host: string; port: number; user: string; secret: string; connectedAt: string }
  | { provider: "gmail"; email: string; secret: string; connectedAt: string };

export async function getConn(userId: string): Promise<InboxConn | null> {
  return getKV().get<InboxConn>(`inbox:${userId}`);
}
export async function saveImap(userId: string, c: ImapConfig) {
  await getKV().set(`inbox:${userId}`, { provider: "imap", host: c.host, port: c.port, user: c.user, secret: encrypt(c.pass), connectedAt: new Date().toISOString() } satisfies InboxConn);
}
export async function saveGmail(userId: string, email: string, refreshToken: string) {
  await getKV().set(`inbox:${userId}`, { provider: "gmail", email, secret: encrypt(refreshToken), connectedAt: new Date().toISOString() } satisfies InboxConn);
}
export async function disconnect(userId: string) {
  await getKV().del(`inbox:${userId}`);
}
export function describe(c: InboxConn | null) {
  if (!c) return null;
  return c.provider === "imap" ? { provider: "imap", account: c.user, host: c.host, connectedAt: c.connectedAt } : { provider: "gmail", account: c.email, connectedAt: c.connectedAt };
}

const imapCfg = (c: Extract<InboxConn, { provider: "imap" }>): ImapConfig => ({ host: c.host, port: c.port, user: c.user, pass: decrypt(c.secret) });

export async function listInbox(c: InboxConn): Promise<InboxMessage[]> {
  if (c.provider === "imap") return listImap(imapCfg(c));
  return listGmail(await accessFromRefresh(decrypt(c.secret)));
}
export async function rawMessage(c: InboxConn, ref: string): Promise<Buffer> {
  if (c.provider === "imap") return fetchImapRaw(imapCfg(c), ref);
  return fetchGmailRaw(await accessFromRefresh(decrypt(c.secret)), ref);
}
export async function applyLabel(c: InboxConn, ref: string, label: "TEGER_DO_NOT_TRUST" | "TEGER_CAUTION") {
  if (c.provider === "imap") return labelImap(imapCfg(c), ref, label);
  return labelGmail(await accessFromRefresh(decrypt(c.secret)), ref, label);
}
