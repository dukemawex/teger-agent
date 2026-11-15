import { describe, expect, it } from "vitest";
import { FIXTURES } from "../src/lib/fixtures";
import { runAgent } from "../src/lib/agent/agent";
import { offlineNet } from "../src/lib/agent/net";

const env = { net: offlineNet, env: {} };

describe("fixtures (deterministic fallback planner, offline)", () => {
  for (const f of FIXTURES) {
    it(`${f.id} → ${f.expected}`, async () => {
      const r = await runAgent({ message: f.message, lists: { block: [], allow: [] }, toolEnv: env });
      expect(r.verdict).toBe(f.expected);
      expect(r.trace.length).toBeLessThanOrEqual(12);
    });
  }

  it("benign email is not flagged and never called safe", async () => {
    const f = FIXTURES.find((x) => x.id === "benign-github")!;
    const r = await runAgent({ message: f.message, lists: { block: [], allow: [] }, toolEnv: env });
    expect(r.evidence.filter((e) => e.weight > 0)).toHaveLength(0);
    expect(r.banner).toBe("No warning signs found.");
    expect(JSON.stringify(r.summary)).not.toMatch(/\bsafe\b/i);
  });

  it("fake renewal triggers the new hackathon detectors", async () => {
    const f = FIXTURES.find((x) => x.id === "fake-renewal")!;
    const r = await runAgent({ message: f.message, lists: { block: [], allow: [] }, toolEnv: env });
    const cats = r.evidence.map((e) => e.category);
    expect(cats).toEqual(expect.arrayContaining(["text_homoglyph", "inconsistent_deadlines", "cited_brand_contact_mismatch", "dmarc_fail"]));
  });

  it.each([
    ["reset-relay", ["code_relay_request", "reset_or_code_storm"]],
    ["oauth-consent", ["oauth_consent_lure", "device_code_phish"]],
    ["hidden-injection", ["secret_material_request", "hidden_prompt_injection"]],
    ["bec-iban", ["payment_change_request", "reply_to_mismatch"]],
    ["qr-parcel", ["qr_code_lure", "parcel_fee_lure"]],
  ])("%s detects %j", async (id, cats) => {
    const f = FIXTURES.find((x) => x.id === id)!;
    const r = await runAgent({ message: f.message, lists: { block: [], allow: [] }, toolEnv: env });
    expect(r.evidence.map((e) => e.category)).toEqual(expect.arrayContaining(cats as string[]));
  });

  it("banner wording is exact", async () => {
    const mal = await runAgent({ message: FIXTURES[0].message, lists: { block: [], allow: [] }, toolEnv: env });
    expect(mal.banner).toBe("Don't trust this. Don't click links, open attachments, reply, or pay.");
  });
});
