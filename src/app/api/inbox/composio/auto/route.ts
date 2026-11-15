/** Turn Composio new-mail auto-scan on/off (GMAIL_NEW_GMAIL_MESSAGE trigger for this account). */
import { currentUser } from "@/lib/server/auth";
import { fail, guard, json, readJson } from "@/lib/server/http";
import { getConn, setComposioTrigger } from "@/lib/mail/inbox";
import { composio } from "@/lib/mail/composio";
export const runtime = "nodejs";
export async function POST(req: Request) {
  const g = guard(req, "auto", 10);
  if (g) return g;
  const me = await currentUser();
  if (!me) return fail("signin_required", 401);
  const c = await getConn(me.id);
  if (c?.provider !== "composio") return fail("Connect Gmail with Composio first.", 400);
  if (!process.env.COMPOSIO_WEBHOOK_SECRET) return fail("Auto-scan needs a Composio webhook (COMPOSIO_WEBHOOK_SECRET) on this deployment. Manual scans work without it.", 400);
  const b = await readJson(req, 200);
  try {
    const api = await composio();
    if (b?.enabled === true && !c.triggerId) await setComposioTrigger(me.id, await api.createTrigger(me.id, c.connectedAccountId));
    if (b?.enabled === false && c.triggerId) { await api.deleteTrigger(c.triggerId).catch(() => undefined); await setComposioTrigger(me.id, undefined); }
    return json({ ok: true, autoScan: b?.enabled === true });
  } catch (e) {
    return fail(`Couldn't change auto-scan (${String((e as Error).message).slice(0, 100)}).`, 502);
  }
}
