/**
 * Composio redirects here after Google consent with ?status=success|failed&connected_account_id=ca_…
 * Query params are not proof of ownership, so we check: (1) a pending attempt exists for this signed-in
 * user with the same state, (2) the account is listed under this user's Composio user_id, gmail, ACTIVE.
 */
import { NextResponse } from "next/server";
import { currentUser } from "@/lib/server/auth";
import { composio, composioEnabled, profileEmailViaComposio } from "@/lib/mail/composio";
import { saveComposio } from "@/lib/mail/inbox";
import { getKV } from "@/lib/server/kv";
import { safeEqual } from "@/lib/server/crypto";
import { baseUrl } from "@/lib/mail/google";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function GET(req: Request) {
  const base = baseUrl(req);
  const back = (n: string) => NextResponse.redirect(`${base}/app?notice=${n}`, 303);
  const me = await currentUser();
  if (!me) return NextResponse.redirect(`${base}/signin?next=/app`, 303);
  if (!composioEnabled()) return back("composio_not_configured");
  const q = new URL(req.url).searchParams;
  const kv = getKV();
  const pending = await kv.get<{ state: string; connectedAccountId: string | null }>(`czpending:${me.id}`);
  const state = q.get("state") ?? "";
  if (!pending || !state || !safeEqual(state, pending.state)) return back("composio_failed");
  await kv.del(`czpending:${me.id}`);
  if (q.get("status") !== "success") return back("composio_failed");
  const ca = q.get("connected_account_id") ?? pending.connectedAccountId ?? "";
  if (!/^[A-Za-z0-9_-]{3,80}$/.test(ca)) return back("composio_failed");
  try {
    const api = await composio();
    const mine = await api.listAccounts(me.id);
    const acct = mine.find((a) => a.id === ca);
    if (!acct || acct.toolkit !== "gmail" || acct.status.toUpperCase() !== "ACTIVE") return back("composio_failed");
    await saveComposio(me.id, ca, await profileEmailViaComposio(me.id, ca));
    return back("gmail_connected");
  } catch (e) {
    console.error("composio callback failed:", String((e as Error).message).slice(0, 200));
    return back("composio_error");
  }
}
