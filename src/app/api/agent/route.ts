import { runAgent, AgentEvent, AgentResult } from "@/lib/agent/agent";
import { getLists, memoryBackend } from "@/lib/agent/memory";
import { offlineNet, realNet } from "@/lib/agent/net";
import { servClient, servModel } from "@/lib/agent/serv";
import { saveAnalysis } from "@/lib/server/history";
import { resolveIdentity } from "@/lib/server/identity";
import { fail, guard, readJson } from "@/lib/server/http";
import { allow } from "@/lib/ratelimit";

export const runtime = "nodejs";
export const maxDuration = 60;
export const dynamic = "force-dynamic";

const str = (v: unknown, n: number) => (typeof v === "string" ? v.slice(0, n) : undefined);
const SOURCES = new Set(["paste", "fixture", "eml", "imap", "gmail", "gmail-auto"]);

export async function POST(req: Request) {
  const g = guard(req, "agent", 20);
  if (g) return g;
  const body = await readJson(req);
  if (!body) return fail("bad_request");
  const id = await resolveIdentity(req);
  if (!id) return fail("no_identity", 401);
  if (!allow(`agent:${id.id}`, 15)) return fail("busy", 429);
  const m = (body.message ?? {}) as Record<string, unknown>;
  const message = { sender: str(m.sender, 300), reply_to: str(m.reply_to, 300), subject: str(m.subject, 500), body: str(m.body, 12_000), headers: str(m.headers, 4000) };
  if (!message.body?.trim() && !message.subject?.trim()) return fail("bad_request");
  const source = typeof body.source === "string" && SOURCES.has(body.source) ? body.source : "paste";
  const inboxRef = typeof body.inboxRef === "string" && /^[A-Za-z0-9]{1,40}$/.test(body.inboxRef) && (source === "imap" || source === "gmail") ? { provider: source as "imap" | "gmail", ref: body.inboxRef } : undefined;

  let lists = { block: [] as string[], allow: [] as string[] };
  try { lists = await getLists(id.id); } catch { /* store unavailable → empty lists */ }

  const enc = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      const send = (e: AgentEvent | { type: "saved"; id: string }) => controller.enqueue(enc.encode(JSON.stringify(e) + "\n"));
      try {
        let final: AgentResult | undefined;
        await runAgent({
          message, lists, memoryBackend: memoryBackend(),
          toolEnv: { net: process.env.TEGER_OFFLINE === "1" ? offlineNet : realNet, env: process.env },
          client: servClient(), model: servModel(),
          onEvent: (e) => { if (e.type === "final") final = e.result; send(e); },
        });
        if (final) {
          try { const item = await saveAnalysis(id.id, source, message, final, inboxRef); send({ type: "saved", id: item.id }); } catch { /* history is best effort */ }
        }
      } catch {
        send({ type: "error", message: "Agent failed. Please try again." });
      } finally {
        controller.close();
      }
    },
  });
  return new Response(stream, { headers: { "content-type": "application/x-ndjson; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" } });
}
