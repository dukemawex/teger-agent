import { cookies } from "next/headers";
import { exchangeCode, GMAIL_SCOPES, userInfo } from "@/lib/mail/google";
import { saveGmail } from "@/lib/mail/inbox";
import { currentUser, normEmail, setSession, upsertGoogleUser } from "@/lib/server/auth";
import { safeEqual } from "@/lib/server/crypto";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function GET(req: Request) {
  const url = new URL(req.url);
  const jar = await cookies();
  const expected = jar.get("tgr_oauth")?.value ?? "";
  jar.delete("tgr_oauth");
  const state = url.searchParams.get("state") ?? "";
  const code = url.searchParams.get("code");
  const back = (q: string) => Response.redirect(new URL(`/app?${q}`, req.url), 302);
  if (!code || !expected || !safeEqual(state, expected)) return back("notice=oauth_failed");
  try {
    const tok = await exchangeCode(req, code);
    const info = await userInfo(tok.access_token);
    const email = normEmail(info.email);
    if (state.startsWith("gmail.")) {
      const me = await currentUser();
      if (!me) return back("notice=signin_required");
      const scopesGiven = (tok.scope ?? "").split(" ");
      if (!tok.refresh_token || !GMAIL_SCOPES.slice(0, 1).every((s) => scopesGiven.includes(s))) return back("notice=gmail_scopes_missing");
      await saveGmail(me.id, email, tok.refresh_token);
      return back("notice=gmail_connected");
    }
    if (!info.email_verified) return back("notice=email_unverified");
    const u = await upsertGoogleUser(email, info.name ?? "");
    await setSession(u.id);
    return back("notice=signed_in");
  } catch {
    return back("notice=oauth_failed");
  }
}
