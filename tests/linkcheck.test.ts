/** "Paste a suspicious link": URL-only input runs the link tools end to end. */
import { describe, expect, it } from "vitest";
import { runAgent } from "../src/lib/agent/agent";
import { Net, offlineNet } from "../src/lib/agent/net";
import { brandHintForHost, normalizeLinkCheck } from "../src/lib/engine/linkCheck";
import { SAMPLE_LINKS } from "../src/lib/fixtures";
import { call } from "./helpers/mocks";

const lists = { block: [], allow: [] };
const daysAgo = (d: number) => new Date(Date.now() - d * 86400000).toISOString();
/** Network mock: the domain was registered 2 days ago and the link lands on a fake PayPal login. */
const phishNet: Net = {
  async fetchJson() { return { events: [{ eventAction: "registration", eventDate: daysAgo(2) }] }; },
  async safeFetch(url) { return { hops: [{ url, status: 302 }], finalUrl: "https://paypa1-secure-login.top/signin", status: 200, contentType: "text/html", body: "<title>PayPal: Log in</title><form action=/x><input type=password></form>", truncated: false }; },
};

describe("normalizeLinkCheck", () => {
  it.each([
    ["https://paypa1-secure-login.top/verify", "https://paypa1-secure-login.top/verify"],
    ["paypa1-secure-login.top/verify", "https://paypa1-secure-login.top/verify"],
    ["  <www.micros0ft-support.com>  ", "https://www.micros0ft-support.com"],
  ])("%j is a link check", (body, link) => {
    const r = normalizeLinkCheck({ body });
    expect(r.linkOnly).toBe(true);
    expect(r.links).toEqual([link]);
    expect(r.message.body).toBe(link);
  });
  it.each([
    "Please verify your account at https://paypal.com today",
    "hello",
    "1.2.3.4",
    "",
  ])("%j is not a link check", (body) => expect(normalizeLinkCheck({ body }).linkOnly).toBe(false));
  it("is not a link check when sender/subject are present", () => {
    expect(normalizeLinkCheck({ sender: "a@b.com", body: "https://x.example" }).linkOnly).toBe(false);
  });
  it("guesses the imitated brand", () => {
    expect(brandHintForHost("paypa1-secure-login.top")?.name).toBe("PayPal");
    expect(brandHintForHost("micros0ft-support.com")?.name).toBe("Microsoft");
    expect(brandHintForHost("www.paypal.com")).toBeUndefined();
    expect(brandHintForHost("example.org")).toBeUndefined();
  });
});

describe("URL-only input end to end", () => {
  it("bare look-alike domain → malicious via link tools (fallback planner, offline)", async () => {
    const r = await runAgent({ message: { body: "paypa1-secure-login.top/verify" }, lists, toolEnv: { net: offlineNet, env: {} } });
    expect(r.mode).toBe("link");
    expect(r.verdict).toBe("malicious");
    expect(r.banner).toBe("Don't trust this. Don't click links, open attachments, reply, or pay.");
    expect(r.trace.filter((s) => s.tool).map((s) => s.tool)).toEqual(["analyze_message", "inspect_domain", "inspect_link", "research_brand", "decide"]);
    expect(r.evidence.map((e) => e.category)).toEqual(expect.arrayContaining(["brand_name_on_untrusted_domain", "text_homoglyph", "domain_not_official_for_brand"]));
    expect(r.trace[0].output).toMatch(/^Link check/);
    expect(r.what_to_do[0]).toMatch(/Don't open this link/);
    expect(r.sender_domain).toBe("paypa1-secure-login.top");
  });

  it("SERV plans the link check; domain age + redirect + credential form are evidence; verdict stays deterministic", async () => {
    const seen: Record<string, unknown>[] = [];
    let turn = 0;
    const client = {
      async create(p: Record<string, unknown>) {
        seen.push(p);
        if (!p.tools) return { choices: [{ message: { content: JSON.stringify({ summary: "This link is safe.", reasons: [], what_to_do: ["Open the link to check."] }) } }] };
        turn++;
        if (turn === 1) return { choices: [{ message: { content: "Plan: resolve the link, check domain age and the brand it imitates, then decide.", tool_calls: [
          call("1", "inspect_link", { why: "central link", url: "https://paypa1-secure-login.top/verify" }),
          call("2", "inspect_domain", { why: "age", domain: "paypa1-secure-login.top" }),
          call("3", "research_brand", { why: "looks like PayPal", brand: "PayPal", link_domain: "paypa1-secure-login.top" }),
        ] } }] };
        return { choices: [{ message: { content: null, tool_calls: [call("4", "decide", { why: "done" })] } }] };
      },
    };
    const r = await runAgent({ message: { body: "https://paypa1-secure-login.top/verify" }, lists, toolEnv: { net: phishNet, env: {} }, client });
    expect(r.planner).toBe("serv");
    expect(r.verdict).toBe("malicious");
    expect(r.evidence.map((e) => e.category)).toEqual(expect.arrayContaining(["newly_registered_domain", "credential_form_on_untrusted_domain", "brand_page_on_untrusted_domain", "brand_name_on_untrusted_domain"]));
    expect(r.summary).not.toMatch(/safe/i);
    expect(r.what_to_do.join(" ")).not.toMatch(/Open the link/);
    expect((seen[0].messages as { content: string }[])[1].content).toContain("mode=link_check");
  });

  it("an official link shows no warning signs (never 'safe')", async () => {
    const r = await runAgent({ message: { body: "https://github.com/login" }, lists, toolEnv: { net: offlineNet, env: {} } });
    expect(r.verdict).toBe("no_threat_detected");
    expect(r.summary).not.toMatch(/\bsafe\b/i);
  });

  it("Confirm scam on a pasted link blocks that domain next time", async () => {
    const r = await runAgent({ message: { body: "https://parcel-redelivery.example/track" }, lists: { block: ["parcel-redelivery.example"], allow: [] }, toolEnv: { net: offlineNet, env: {} } });
    expect(r.verdict).toBe("malicious");
    expect(r.learned[0]).toMatch(/^Teger learned/);
  });

  for (const s of SAMPLE_LINKS) {
    it(`sample link chip ${s.url} → ${s.expected}`, async () => {
      const r = await runAgent({ message: { body: s.url }, lists, toolEnv: { net: offlineNet, env: {} } });
      expect(r.verdict).toBe(s.expected);
    });
  }
});
