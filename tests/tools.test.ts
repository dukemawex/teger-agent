/** Agent tools with a mocked network: RDAP domain age, SSRF-safe link resolution, scoping. */
import { describe, expect, it } from "vitest";
import { initState, runTool } from "../src/lib/agent/tools";
import { BlockedTargetError, isBlockedIp, Net, SafeFetchResult } from "../src/lib/agent/net";

const daysAgo = (d: number) => new Date(Date.now() - d * 86400000).toISOString();
const rdapNet = (fn: (url: string) => unknown): Net => ({
  async safeFetch() { throw new Error("offline"); },
  async fetchJson(url) { const r = fn(url); if (r instanceof Error) throw r; return r; },
});
const linkNet = (r: Partial<SafeFetchResult> | Error): Net => ({
  async safeFetch(url) { if (r instanceof Error) throw r; return { hops: [{ url, status: 302 }], finalUrl: url, status: 200, contentType: "text/html", body: "", truncated: false, ...r }; },
  async fetchJson() { throw new Error("offline"); },
});
const msg = { sender: "Billing <billing@renew-mailbox.top>", subject: "Renew", body: "Renew at https://renew-mailbox.top/login now." };

describe("inspect_domain (RDAP domain age)", () => {
  const run = async (net: Net, domain = "renew-mailbox.top") => {
    const s = initState(msg, { block: [], allow: [] });
    const r = await runTool("inspect_domain", { why: "t", domain }, s, { net, env: {} });
    return { r, s };
  };
  it("flags a domain registered days ago", async () => {
    const { r } = await run(rdapNet(() => ({ events: [{ eventAction: "registration", eventDate: daysAgo(3) }] })));
    expect(r.evidence_added.map((e) => e.category)).toContain("newly_registered_domain");
    expect(r.output.age_days).toBe(3);
  });
  it("flags a young (< 6 months) domain at medium", async () => {
    const { r } = await run(rdapNet(() => ({ events: [{ eventAction: "registration", eventDate: daysAgo(90) }] })));
    expect(r.evidence_added[0]).toMatchObject({ category: "young_domain", severity: "medium" });
  });
  it("does not flag an old domain", async () => {
    const { r } = await run(rdapNet(() => ({ events: [{ eventAction: "registration", eventDate: daysAgo(4000) }] })));
    expect(r.evidence_added).toHaveLength(0);
  });
  it("RDAP 404 → age unknown, no evidence, coverage not reduced", async () => {
    const { r, s } = await run(rdapNet(() => new Error("HTTP 404")));
    expect(r.output.rdap).toBe("not_found");
    expect(r.summary).toMatch(/unknown/);
    expect(s.reports.every((x) => x.status === "ok")).toBe(true);
  });
  it("RDAP outage → reported as unavailable, never as a finding", async () => {
    const { r } = await run(rdapNet(() => new Error("ETIMEDOUT")));
    expect(String(r.output.rdap)).toMatch(/^unavailable/);
    expect(r.evidence_added).toHaveLength(0);
  });
  it("uses the Verisign RDAP endpoint first for .com", async () => {
    const seen: string[] = [];
    const s = initState({ sender: "a@example-shop.com", body: "hi" }, { block: [], allow: [] });
    await runTool("inspect_domain", { why: "t", domain: "example-shop.com" }, s, { net: rdapNet((u) => { seen.push(u); return { events: [] }; }), env: {} });
    expect(seen[0]).toMatch(/^https:\/\/rdap\.verisign\.com\/com\//);
  });
  it("refuses domains that are not in the message", async () => {
    const { r } = await run(rdapNet(() => ({})), "internal.corp");
    expect(r.summary).toMatch(/^Refused/);
  });
});

describe("inspect_link (SSRF-safe resolution)", () => {
  const run = async (net: Net, url = "https://renew-mailbox.top/login") => {
    const s = initState(msg, { block: [], allow: [] });
    return runTool("inspect_link", { why: "t", url }, s, { net, env: {} });
  };
  it("detects a cross-domain redirect to a credential form", async () => {
    const r = await run(linkNet({ hops: [{ url: "https://renew-mailbox.top/login", status: 302 }], finalUrl: "https://paypa1-secure.xyz/signin", body: "<title>PayPal Login</title><form action=/p><input type=password></form>" }));
    const cats = r.evidence_added.map((e) => e.category);
    expect(cats).toEqual(expect.arrayContaining(["redirect_to_other_domain", "credential_form_on_untrusted_domain", "brand_page_on_untrusted_domain"]));
    expect(r.output.final_url).toBe("https://paypa1-secure.xyz/signin");
  });
  it("reports a blocked (private) target without crashing", async () => {
    const r = await run(linkNet(new BlockedTargetError("Target resolves to a private or reserved address.")));
    expect(r.output.fetch).toMatch(/^blocked/);
  });
  it("reports an unreachable site", async () => {
    const r = await run(linkNet(new Error("ECONNREFUSED")));
    expect(r.output.fetch).toMatch(/^unreachable/);
  });
  it("refuses links that are not in the message", async () => {
    expect((await run(linkNet({}), "http://169.254.169.254/latest/meta-data")).summary).toMatch(/^Refused/);
  });
});

describe("SSRF guard edge cases", () => {
  it.each(["::ffff:7f00:1", "::ffff:a9fe:a9fe", "::7f00:1", "fe80::1", "ff02::1", "2001:db8::1", "224.0.0.1", "198.18.0.1"])("blocks %s", (ip) => expect(isBlockedIp(ip)).toBe(true));
  it.each(["1.1.1.1", "2606:4700:4700::1111"])("allows %s", (ip) => expect(isBlockedIp(ip)).toBe(false));
  it("treats non-IP input as blocked", () => expect(isBlockedIp("not-an-ip")).toBe(true));
});

describe("research_brand", () => {
  it("marks a non-official domain for a known brand", async () => {
    const s = initState(msg, { block: [], allow: [] });
    const r = await runTool("research_brand", { why: "t", brand: "PayPal", link_domain: "renew-mailbox.top" }, s, { net: rdapNet(() => ({})), env: {} });
    expect(r.output.is_official).toBe(false);
    expect(r.evidence_added[0].category).toBe("domain_not_official_for_brand");
  });
  it("unknown tool names are rejected", async () => {
    const s = initState(msg, { block: [], allow: [] });
    expect((await runTool("rm_rf", {}, s, { net: rdapNet(() => ({})), env: {} })).output.error).toBe("unknown_tool");
  });
});

describe("RDAP bootstrap", () => {
  it("queries the registry's RDAP server from the IANA bootstrap for non-.com TLDs", async () => {
    const seen: string[] = [];
    const net = rdapNet((u) => {
      seen.push(u);
      if (u.includes("data.iana.org")) return { services: [[["top"], ["https://rdap.example-registry.top/top/"]]] };
      return { events: [{ eventAction: "registration", eventDate: daysAgo(1) }] };
    });
    const s = initState(msg, { block: [], allow: [] });
    const r = await runTool("inspect_domain", { why: "t", domain: "renew-mailbox.top" }, s, { net, env: {} });
    expect(seen).toContain("https://rdap.example-registry.top/top/domain/renew-mailbox.top");
    expect(r.evidence_added[0].category).toBe("newly_registered_domain");
  });
});
