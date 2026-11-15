import { loginPassword, normEmail, publicUser, setSession } from "@/lib/server/auth";
import { fail, guard, json, readJson } from "@/lib/server/http";
export const runtime = "nodejs";
export async function POST(req: Request) {
  const g = guard(req, "auth", 10);
  if (g) return g;
  const b = await readJson(req, 2000);
  const u = await loginPassword(normEmail(b?.email), typeof b?.password === "string" ? b.password : "");
  if (!u) return fail("Email or password is incorrect.", 401);
  await setSession(u.id);
  return json({ user: publicUser(u) });
}
