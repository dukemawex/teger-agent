/** Create a verification DRAFT (never sent) for payment / bank-detail change messages. */
import { currentUser } from "@/lib/server/auth";
import { fail, guard, json, readJson } from "@/lib/server/http";
import { getConn } from "@/lib/mail/inbox";
import { verificationDraftViaComposio } from "@/lib/mail/composio";
export const runtime = "nodejs";
export const maxDuration = 60;
export async function POST(req: Request) {
  const g = guard(req, "draft", 10);
  if (g) return g;
  const me = await currentUser();
  if (!me) return fail("signin_required", 401);
  const c = await getConn(me.id);
  if (c?.provider !== "composio") return fail("Connect Gmail with Composio to create drafts.", 400);
  const b = await readJson(req, 4000);
  const subject = typeof b?.subject === "string" ? b.subject.slice(0, 200) : "";
  const sender = typeof b?.sender === "string" ? b.sender.slice(0, 200) : "";
  try {
    await verificationDraftViaComposio(me.id, c.connectedAccountId, subject, sender);
    return json({ ok: true });
  } catch (e) {
    return fail(`Couldn't create the draft (${String((e as Error).message).slice(0, 100)}).`, 502);
  }
}
