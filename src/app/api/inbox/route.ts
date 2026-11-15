import { currentUser } from "@/lib/server/auth";
import { fail, guard, json } from "@/lib/server/http";
import { describe, disconnect, getConn, listInbox } from "@/lib/mail/inbox";
export const runtime = "nodejs";
export const maxDuration = 60;
export const dynamic = "force-dynamic";
export async function GET() {
  const me = await currentUser();
  if (!me) return fail("signin_required", 401);
  const c = await getConn(me.id);
  if (!c) return json({ connection: null, messages: [] });
  try {
    return json({ connection: describe(c), messages: await listInbox(c) });
  } catch (e) {
    return json({ connection: describe(c), messages: [], error: `Couldn't read the inbox (${String((e as Error).message).slice(0, 80)}). Reconnect it if your app password or access changed.` });
  }
}
export async function DELETE(req: Request) {
  const g = guard(req, "inbox", 20);
  if (g) return g;
  const me = await currentUser();
  if (!me) return fail("signin_required", 401);
  await disconnect(me.id);
  return json({ ok: true });
}
