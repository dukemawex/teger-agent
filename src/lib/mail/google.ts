/**
 * Google OAuth (sign-in + Gmail). Enabled when GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET are set.
 * Gmail scopes: gmail.readonly (list/read), gmail.labels (create TEGER_* labels),
 * gmail.modify (apply a label to a message). Teger never sends, trashes or deletes.
 */
import { InboxMessage } from "./imap";

export const GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/gmail.labels", "https://www.googleapis.com/auth/gmail.modify"];
export const SIGNIN_SCOPES = ["openid", "email", "profile"];

export const googleEnabled = () => !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);

export function baseUrl(req: Request): string {
  if (process.env.APP_URL) return process.env.APP_URL.replace(/\/$/, "");
  const h = req.headers.get("x-forwarded-host") ?? req.headers.get("host");
  const proto = req.headers.get("x-forwarded-proto") ?? "https";
  return `${proto}://${h}`;
}

export function authUrl(req: Request, state: string, mode: "signin" | "gmail"): string {
  const p = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID!,
    redirect_uri: `${baseUrl(req)}/api/auth/google/callback`,
    response_type: "code",
    scope: (mode === "gmail" ? [...SIGNIN_SCOPES, ...GMAIL_SCOPES] : SIGNIN_SCOPES).join(" "),
    state,
    include_granted_scopes: "true",
    prompt: mode === "gmail" ? "consent" : "select_account",
    ...(mode === "gmail" ? { access_type: "offline" } : {}),
  });
  return `https://accounts.google.com/o/oauth2/v2/auth?${p}`;
}

export async function exchangeCode(req: Request, code: string) {
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ code, client_id: process.env.GOOGLE_CLIENT_ID!, client_secret: process.env.GOOGLE_CLIENT_SECRET!, redirect_uri: `${baseUrl(req)}/api/auth/google/callback`, grant_type: "authorization_code" }),
  });
  if (!r.ok) throw new Error(`token exchange failed (${r.status})`);
  return (await r.json()) as { access_token: string; refresh_token?: string; id_token?: string; scope?: string };
}

export async function userInfo(accessToken: string) {
  const r = await fetch("https://openidconnect.googleapis.com/v1/userinfo", { headers: { authorization: `Bearer ${accessToken}` } });
  if (!r.ok) throw new Error("userinfo failed");
  return (await r.json()) as { email: string; email_verified?: boolean; name?: string };
}

export async function accessFromRefresh(refreshToken: string): Promise<string> {
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ refresh_token: refreshToken, client_id: process.env.GOOGLE_CLIENT_ID!, client_secret: process.env.GOOGLE_CLIENT_SECRET!, grant_type: "refresh_token" }),
  });
  if (!r.ok) throw new Error(`refresh failed (${r.status})`);
  return ((await r.json()) as { access_token: string }).access_token;
}

const G = "https://gmail.googleapis.com/gmail/v1/users/me";

async function gfetch<T>(token: string, path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(G + path, { ...init, headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...(init?.headers ?? {}) } });
  if (!r.ok) throw new Error(`Gmail API ${r.status}`);
  return r.json() as Promise<T>;
}

export async function listGmail(token: string, limit = 20): Promise<InboxMessage[]> {
  const list = await gfetch<{ messages?: { id: string }[] }>(token, `/messages?maxResults=${limit}&labelIds=INBOX`);
  const out = await Promise.all((list.messages ?? []).map(async ({ id }) => {
    const m = await gfetch<{ id: string; snippet?: string; payload?: { headers?: { name: string; value: string }[] }; internalDate?: string }>(token, `/messages/${id}?format=metadata&metadataHeaders=From&metadataHeaders=Subject`);
    const h = (n: string) => m.payload?.headers?.find((x) => x.name.toLowerCase() === n)?.value ?? "";
    return { ref: id, from: h("from"), subject: h("subject") || "(no subject)", date: m.internalDate ? new Date(Number(m.internalDate)).toISOString() : undefined, snippet: m.snippet?.slice(0, 140) };
  }));
  return out;
}

export async function fetchGmailRaw(token: string, id: string): Promise<Buffer> {
  if (!/^[A-Za-z0-9]{6,40}$/.test(id)) throw new Error("bad id");
  const m = await gfetch<{ raw: string }>(token, `/messages/${id}?format=raw`);
  return Buffer.from(m.raw, "base64url");
}

export async function labelGmail(token: string, id: string, label: "TEGER_DO_NOT_TRUST" | "TEGER_CAUTION"): Promise<string> {
  if (!/^[A-Za-z0-9]{6,40}$/.test(id)) throw new Error("bad id");
  const labels = await gfetch<{ labels: { id: string; name: string }[] }>(token, "/labels");
  let l = labels.labels.find((x) => x.name === label);
  if (!l) l = await gfetch<{ id: string; name: string }>(token, "/labels", { method: "POST", body: JSON.stringify({ name: label, labelListVisibility: "labelShow", messageListVisibility: "show" }) });
  await gfetch(token, `/messages/${id}/modify`, { method: "POST", body: JSON.stringify({ addLabelIds: [l.id] }) });
  return "gmail-label";
}
