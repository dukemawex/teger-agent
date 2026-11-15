import { currentUser } from "@/lib/server/auth";
import { fail, json } from "@/lib/server/http";
import { getConn, rawMessage } from "@/lib/mail/inbox";
import { parseRawEmail } from "@/lib/mail/parse";
export const runtime = "nodejs";
export const maxDuration = 60;
export const dynamic = "force-dynamic";
export async function GET(req: Request) {
  const me = await currentUser();
  if (!me) return fail("signin_required", 401);
  const ref = new URL(req.url).searchParams.get("ref") ?? "";
  if (!/^[A-Za-z0-9]{1,40}$/.test(ref)) return fail("bad_request");
  const c = await getConn(me.id);
  if (!c) return fail("not_connected", 404);
  try {
    return json({ provider: c.provider, ref, message: await parseRawEmail(await rawMessage(c, ref)) });
  } catch (e) {
    return fail(`Couldn't fetch that message (${String((e as Error).message).slice(0, 80)}).`, 502);
  }
}
