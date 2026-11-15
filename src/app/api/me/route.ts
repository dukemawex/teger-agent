import { getLists, memoryBackend } from "@/lib/agent/memory";
import { publicUser } from "@/lib/server/auth";
import { resolveIdentity } from "@/lib/server/identity";
import { json } from "@/lib/server/http";
import { googleEnabled } from "@/lib/mail/google";
import { describe, getConn } from "@/lib/mail/inbox";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const id = await resolveIdentity(req);
  return json({
    user: id?.user ? publicUser(id.user) : null,
    guest: !!id?.guest,
    lists: id ? await getLists(id.id) : { block: [], allow: [] },
    inbox: id?.user ? describe(await getConn(id.user.id)) : null,
    google: googleEnabled(),
    serv: !!process.env.SERV_API_KEY,
    model: process.env.SERV_MODEL || "gpt-5.4-mini",
    memory: memoryBackend(),
  });
}
