import { currentUser } from "@/lib/server/auth";
import { fail, guard, json, readJson } from "@/lib/server/http";
import { applyLabel, getConn } from "@/lib/mail/inbox";
export const runtime = "nodejs";
export const maxDuration = 60;
export async function POST(req: Request) {
  const g = guard(req, "label", 20);
  if (g) return g;
  const me = await currentUser();
  if (!me) return fail("signin_required", 401);
  const b = await readJson(req, 1000);
  const ref = typeof b?.ref === "string" && /^[A-Za-z0-9]{1,40}$/.test(b.ref) ? b.ref : "";
  const label = b?.label === "TEGER_DO_NOT_TRUST" || b?.label === "TEGER_CAUTION" ? b.label : null;
  if (!ref || !label) return fail("bad_request");
  const c = await getConn(me.id);
  if (!c) return fail("not_connected", 404);
  try {
    return json({ ok: true, how: await applyLabel(c, me.id, ref, label), label });
  } catch (e) {
    return fail(`Couldn't apply the label (${String((e as Error).message).slice(0, 80)}).`, 502);
  }
}
