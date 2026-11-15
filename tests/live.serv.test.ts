import { it } from "vitest";
import { FIXTURES } from "../src/lib/fixtures";
import { runAgent } from "../src/lib/agent/agent";
import { realNet } from "../src/lib/agent/net";
import { servClient, servModel } from "../src/lib/agent/serv";
it.runIf(!!process.env.SERV_API_KEY && process.env.LIVE === "1")("live SERV", async () => {
  for (const id of (process.env.LIVE_IDS ?? "fake-renewal,benign-github").split(",")) {
    const f = FIXTURES.find((x) => x.id === id)!;
    const t = Date.now();
    const r = await runAgent({ message: f.message, lists: { block: [], allow: [] }, toolEnv: { net: realNet, env: process.env }, client: servClient(), model: servModel() });
    process.stderr.write(`\n=== ${id} expected ${f.expected} got ${r.verdict} planner=${r.planner} ${r.planner_note ?? ""} ${Date.now() - t}ms usage=${JSON.stringify(r.usage)}\n`);
    for (const s of r.trace) process.stderr.write(`  [${s.phase}] ${s.tool ?? ""} by=${s.by} why=${s.why ?? ""} :: ${s.output}\n`);
    process.stderr.write(`  summary: ${r.summary}\n  todo: ${r.what_to_do.join(" | ")}\n  reasons: ${r.top_reasons.map((x) => x.title).join(" | ")}\n`);
  }
}, 180000);
