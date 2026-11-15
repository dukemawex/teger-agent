import { currentUser } from "@/lib/server/auth";
import { fail, guard, json, readJson } from "@/lib/server/http";
import { testImap, validateImapConfig } from "@/lib/mail/imap";
import { saveImap } from "@/lib/mail/inbox";
export const runtime = "nodejs";
export const maxDuration = 60;
export async function POST(req: Request) {
  const g = guard(req, "imap", 8);
  if (g) return g;
  const me = await currentUser();
  if (!me) return fail("signin_required", 401);
  const b = await readJson(req, 4000);
  const cfg = validateImapConfig((b ?? {}) as never);
  if (typeof cfg === "string") return fail(cfg);
  try {
    const t = await testImap(cfg);
    await saveImap(me.id, cfg);
    return json({ ok: true, messages: t.messages });
  } catch (e) {
    const msg = String((e as Error & { responseText?: string }).responseText ?? (e as Error).message ?? "");
    return fail(/auth|credential|invalid|login/i.test(msg) ? "The server rejected the login. Use an app password (not your normal password) and check the address." : `Couldn't connect to ${cfg.host}: ${msg.slice(0, 100)}`, 400);
  }
}
