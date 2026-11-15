import { clearSession } from "@/lib/server/auth";
import { guard, json } from "@/lib/server/http";
export async function POST(req: Request) {
  const g = guard(req, "auth", 30);
  if (g) return g;
  await clearSession();
  return json({ ok: true });
}
