import { currentUser } from "@/lib/server/auth";
import { fail, json } from "@/lib/server/http";
import { fetchMessage, getConn } from "@/lib/mail/inbox";
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
    // Composio-connected Gmail is still Gmail as far as history and labels are concerned.
    return json({ provider: c.provider === "imap" ? "imap" : "gmail", via: c.provider, ref, message: await fetchMessage(c, me.id, ref) });
  } catch (e) {
    return fail(`Couldn't fetch that message (${String((e as Error).message).slice(0, 100)}).`, 502);
  }
}
