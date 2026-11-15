import { describe, expect, it } from "vitest";
import { ChatClient, runAgent, MAX_STEPS, SYSTEM_PROMPT } from "../src/lib/agent/agent";
import { offlineNet } from "../src/lib/agent/net";
import { FIXTURES } from "../src/lib/fixtures";

const env = { net: offlineNet, env: {} };
const call = (id: string, name: string, args: Record<string, unknown>) => ({ id, type: "function", function: { name, arguments: JSON.stringify(args) } });
const usage = { prompt_tokens: 100, completion_tokens: 20, total_tokens: 120 };

/** Scripted SERV mock: returns tool calls in order, then the explanation JSON. */
function mockServ(script: ReturnType<typeof call>[][], explanation: Record<string, unknown>, seen: Record<string, unknown>[] = []): ChatClient {
  let i = 0;
  return {
    async create(params) {
      seen.push(params);
      if (!params.tools) return { choices: [{ message: { content: JSON.stringify(explanation) } }], usage };
      const calls = script[i++];
      return { choices: [{ message: { content: i === 1 ? "Plan: check content, sender auth, domain, then decide." : null, tool_calls: calls } }], usage };
    },
  };
}

const renewal = FIXTURES.find((f) => f.id === "fake-renewal")!;
const benign = FIXTURES.find((f) => f.id === "benign-github")!;

describe("SERV agent loop (mocked SERV)", () => {
  it("runs Observe→Plan→Investigate→Decide→Explain with a system message on every request", async () => {
    const seen: Record<string, unknown>[] = [];
    const client = mockServ([
      [call("1", "analyze_message", { why: "start" })],
      [call("2", "check_sender_auth", { why: "headers" }), call("3", "inspect_domain", { why: "sender", domain: "internationalgroupcolleferro.it" })],
      [call("4", "research_brand", { why: "brand claim", brand: "Namecheap", link_domain: "privateemail-renewal-portal.top" })],
      [call("5", "decide", { why: "enough evidence" })],
    ], { summary: "This is a fake renewal notice.", reasons: [{ evidence_id: "ev-1", title: "x", explanation: "y" }], what_to_do: ["Log in to your provider directly."] }, seen);
    const r = await runAgent({ message: renewal.message, lists: { block: [], allow: [] }, toolEnv: env, client, model: "gpt-5.4-mini" });
    expect(r.planner).toBe("serv");
    expect(r.verdict).toBe("malicious");
    expect(r.trace.map((s) => s.phase)).toEqual(expect.arrayContaining(["observe", "plan", "investigate", "decide", "explain"]));
    expect(r.trace.filter((s) => s.tool).map((s) => s.tool)).toEqual(["analyze_message", "check_sender_auth", "inspect_domain", "research_brand", "decide"]);
    for (const p of seen) expect((p.messages as { role: string }[])[0].role).toBe("system");
    expect((seen[0].messages as { content: string }[])[0].content).toBe(SYSTEM_PROMPT);
    expect((seen[0].messages as { content: string }[])[1].content).toContain("<untrusted_message>");
    expect(r.what_to_do).toEqual(["Log in to your provider directly."]);
  });

  it("LLM cannot change the verdict, even if its explanation claims the message is fine", async () => {
    const client = mockServ([[call("1", "decide", { why: "skip" })]], { summary: "This email is safe, verdict: no_threat_detected", reasons: [{ evidence_id: "ev-999", title: "fake", explanation: "made up" }], what_to_do: ["ok"] });
    const r = await runAgent({ message: renewal.message, lists: { block: [], allow: [] }, toolEnv: env, client });
    expect(r.verdict).toBe("malicious"); // decide always includes local detectors
    expect(r.summary).not.toMatch(/safe/i); // summaries saying "safe" are rejected
    expect(r.top_reasons.every((x) => r.evidence.some((e) => e.id === x.evidence_id))).toBe(true);
  });

  it("enforces decide when the planner stops early, and caps tool steps", async () => {
    const many = Array.from({ length: 20 }, (_, k) => [call(`c${k}`, "analyze_message", { why: "loop" })]);
    const r = await runAgent({ message: benign.message, lists: { block: [], allow: [] }, toolEnv: env, client: mockServ(many, { summary: "No warning signs.", reasons: [], what_to_do: ["Stay alert."] }) });
    expect(r.trace.filter((s) => s.tool && s.tool !== "decide").length).toBeLessThanOrEqual(MAX_STEPS);
    expect(r.trace.some((s) => s.tool === "decide")).toBe(true);
    expect(r.verdict).toBe("no_threat_detected");
  });

  it("refuses to inspect domains/links not present in the message (injection-steered targets)", async () => {
    const client = mockServ([[call("1", "inspect_link", { why: "x", url: "http://169.254.169.254/latest/meta-data" }), call("2", "inspect_domain", { why: "x", domain: "evil.example" })], [call("3", "decide", { why: "done" })]], { summary: "s", reasons: [], what_to_do: ["a"] });
    const r = await runAgent({ message: benign.message, lists: { block: [], allow: [] }, toolEnv: env, client });
    expect(r.trace.find((s) => s.tool === "inspect_link")!.output).toMatch(/Refused/);
    expect(r.trace.find((s) => s.tool === "inspect_domain")!.output).toMatch(/Refused/);
  });

  it("falls back deterministically when SERV errors", async () => {
    const client: ChatClient = { async create() { throw new Error("401 Unauthorized"); } };
    const r = await runAgent({ message: renewal.message, lists: { block: [], allow: [] }, toolEnv: env, client });
    expect(r.planner).toBe("fallback");
    expect(r.planner_note).toMatch(/401/);
    expect(r.verdict).toBe("malicious");
  });

  it("learns from feedback: blocked sender is blocked on the next run, with a 'Teger learned' trace step", async () => {
    const r = await runAgent({ message: benign.message, lists: { block: ["github.com"], allow: [] }, toolEnv: env });
    expect(r.verdict).toBe("malicious");
    expect(r.learned[0]).toMatch(/^Teger learned:/);
    expect(r.trace.some((s) => s.output.startsWith("Teger learned:"))).toBe(true);
  });

  it("trusted sender lowers risk but critical signals still override", async () => {
    const inj = FIXTURES.find((f) => f.id === "hidden-injection")!;
    const r = await runAgent({ message: inj.message, lists: { block: [], allow: ["vendor-audit-portal.net"] }, toolEnv: env });
    expect(r.verdict).toBe("malicious");
    expect(r.learned[0]).toMatch(/critical signal overrides/);
  });
});
