/** Start a Composio-hosted Gmail connection for the signed-in Teger account. */
import { NextResponse } from "next/server";
import { currentUser } from "@/lib/server/auth";
import { allow, clientIp } from "@/lib/ratelimit";
import { composio, composioEnabled } from "@/lib/mail/composio";
import { getKV } from "@/lib/server/kv";
import { randomId } from "@/lib/server/crypto";
import { baseUrl } from "@/lib/mail/google";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function GET(req: Request) {
  const base = baseUrl(req);
  const back = (n: string) => NextResponse.redirect(`${base}/app?notice=${n}`, 303);
  const me = await currentUser();
  if (!me) return NextResponse.redirect(`${base}/signin?next=/app`, 303);
  if (!composioEnabled()) return back("composio_not_configured");
  if (!allow(`composio-link:${clientIp(req)}`, 10)) return back("busy");
  try {
    const state = randomId(12);
    const { redirectUrl, connectedAccountId } = await (await composio()).createLink(me.id, `${base}/api/inbox/composio/callback?state=${state}`);
    // Remember this attempt so the callback can be tied to this user and this browser flow.
    await getKV().set(`czpending:${me.id}`, { state, connectedAccountId: connectedAccountId ?? null, at: Date.now() }, 900);
    return NextResponse.redirect(redirectUrl, 303);
  } catch (e) {
    const msg = String((e as Error).message);
    console.error("composio link failed:", msg.slice(0, 200));
    return back(/permission|\b403\b/i.test(msg) ? "composio_permissions" : "composio_error");
  }
}
