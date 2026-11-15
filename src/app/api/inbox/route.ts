import { currentUser } from "@/lib/server/auth";
import { fail, guard, json } from "@/lib/server/http";
import { describe, disconnect, getConn, listInbox } from "@/lib/mail/inbox";
import { composio } from "@/lib/mail/composio";
import { triage } from "@/lib/mail/triage";
export const runtime = "nodejs";
export const maxDuration = 60;
export const dynamic = "force-dynamic";
export async function GET(req: Request) {
  const me = await currentUser();
  if (!me) return fail("signin_required", 401);
  const c = await getConn(me.id);
  if (!c) return json({ connection: null, messages: [] });
  const suspiciousOnly = new URL(req.url).searchParams.get("filter") === "suspicious";
  try {
    const all = (await listInbox(c, me.id)).map((m) => ({ ...m, triage: triage({ sender: m.from, subject: m.subject, body: m.snippet ?? "" }) }));
    return json({ connection: describe(c), messages: suspiciousOnly ? all.filter((m) => m.triage.verdict !== "no_threat_detected") : all, total: all.length });
  } catch (e) {
    return json({ connection: describe(c), messages: [], error: `Couldn't read the inbox (${String((e as Error).message).slice(0, 100)}). Reconnect it if access changed.` });
  }
}
export async function DELETE(req: Request) {
  const g = guard(req, "inbox", 20);
  if (g) return g;
  const me = await currentUser();
  if (!me) return fail("signin_required", 401);
  const c = await getConn(me.id);
  let remote = "";
  if (c?.provider === "composio") {
    // Revoke at Composio too (best effort), so the Gmail grant doesn't linger.
    try {
      const api = await composio();
      if (c.triggerId) await api.deleteTrigger(c.triggerId).catch(() => undefined);
      await api.deleteAccount(c.connectedAccountId);
      remote = "revoked";
    } catch { remote = "local_only"; }
  }
  await disconnect(me.id);
  return json({ ok: true, remote });
}
