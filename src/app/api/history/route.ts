import { listHistory } from "@/lib/server/history";
import { resolveIdentity } from "@/lib/server/identity";
import { json } from "@/lib/server/http";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function GET(req: Request) {
  const id = await resolveIdentity(req);
  return json({ items: id ? await listHistory(id.id) : [] });
}
