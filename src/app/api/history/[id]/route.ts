import { getAnalysis } from "@/lib/server/history";
import { resolveIdentity } from "@/lib/server/identity";
import { fail, json } from "@/lib/server/http";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const id = await resolveIdentity(req);
  if (!id) return fail("no_identity", 401);
  const rec = await getAnalysis(id.id, (await ctx.params).id);
  return rec ? json(rec) : fail("not_found", 404);
}
