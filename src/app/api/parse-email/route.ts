import { fail, guard, json, readJson } from "@/lib/server/http";
import { parseRawEmail } from "@/lib/mail/parse";
export const runtime = "nodejs";
export async function POST(req: Request) {
  const g = guard(req, "parse", 30);
  if (g) return g;
  const b = await readJson(req, 3_000_000);
  if (typeof b?.raw !== "string" || !b.raw.trim()) return fail("bad_request");
  try {
    return json({ message: await parseRawEmail(b.raw) });
  } catch {
    return fail("Couldn't read that email file.");
  }
}
