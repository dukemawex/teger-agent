import { createPasswordUser, normEmail, publicUser, setSession, validEmail } from "@/lib/server/auth";
import { fail, guard, json, readJson } from "@/lib/server/http";
export const runtime = "nodejs";
export async function POST(req: Request) {
  const g = guard(req, "auth", 10);
  if (g) return g;
  const b = await readJson(req, 2000);
  const email = normEmail(b?.email);
  const password = typeof b?.password === "string" ? b.password : "";
  const name = typeof b?.name === "string" ? b.name.trim() : "";
  if (!validEmail(email)) return fail("Enter a valid email address.");
  if (password.length < 8 || password.length > 200) return fail("Use a password of at least 8 characters.");
  const u = await createPasswordUser(email, password, name);
  if (u === "exists") return fail("An account with this email already exists. Sign in instead.", 409);
  await setSession(u.id);
  return json({ user: publicUser(u) });
}
