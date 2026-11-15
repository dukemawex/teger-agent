import { cookies } from "next/headers";
import { authUrl, googleEnabled } from "@/lib/mail/google";
import { currentUser } from "@/lib/server/auth";
import { randomId } from "@/lib/server/crypto";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function GET(req: Request) {
  const mode = new URL(req.url).searchParams.get("mode") === "gmail" ? "gmail" : "signin";
  if (!googleEnabled()) return Response.redirect(new URL(`/app?notice=google_not_configured`, req.url), 302);
  if (mode === "gmail" && !(await currentUser())) return Response.redirect(new URL(`/signin?next=/app`, req.url), 302);
  const state = `${mode}.${randomId(16)}`;
  (await cookies()).set("tgr_oauth", state, { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax", path: "/", maxAge: 600 });
  return Response.redirect(authUrl(req, state, mode), 302);
}
