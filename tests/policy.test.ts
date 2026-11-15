/** The verdict engine is a pure function of evidence and detector coverage. */
import { describe, expect, it } from "vitest";
import { BANNERS, decide, MALICIOUS_THRESHOLD, SUSPICIOUS_THRESHOLD } from "../src/lib/engine/policy";
import { Evidence, Severity, SEVERITY_WEIGHT } from "../src/lib/engine/types";

let n = 0;
const ev = (severity: Severity, category = `c${++n}`, detector = `d${n}`, weight = SEVERITY_WEIGHT[severity]): Evidence => ({ id: `ev-${n}`, detector, category, tactic: "t", severity, weight, description: "x" });
const ok = [{ name: "a", status: "ok" as const, required: true }];

describe("deterministic policy", () => {
  it("no evidence + full coverage → no_threat_detected, never 'safe'", () => {
    const d = decide([], ok);
    expect(d.verdict).toBe("no_threat_detected");
    expect(d.banner).toBe("No warning signs found.");
    expect(Object.values(BANNERS).join(" ")).not.toMatch(/\bsafe\b/i);
  });
  it("no evidence + a required detector failed → unknown", () => {
    expect(decide([], [{ name: "a", status: "error", required: true }]).verdict).toBe("unknown");
    expect(decide([], [{ name: "a", status: "error", required: false }]).verdict).toBe("no_threat_detected");
  });
  it(`score ≥ ${SUSPICIOUS_THRESHOLD} → suspicious, ≥ ${MALICIOUS_THRESHOLD} → malicious`, () => {
    expect(decide([ev("medium"), ev("low")], ok).verdict).toBe("suspicious"); // 26
    expect(decide([ev("high"), ev("high")], ok).verdict).toBe("malicious"); // 70
    expect(decide([ev("medium")], ok).verdict).toBe("no_threat_detected"); // 18
  });
  it("any critical finding is at least suspicious", () => {
    expect(decide([ev("critical", "x", "d", 10)], ok).verdict).toBe("suspicious");
  });
  it("user block list forces malicious", () => {
    expect(decide([ev("critical", "user_blocklisted", "feedback_memory", 0)], ok).verdict).toBe("malicious");
  });
  it("trust mark (negative weight) can lower a score but never below 0", () => {
    const d = decide([ev("medium"), ev("low"), ev("info", "user_allowlisted", "feedback_memory", -30)], ok);
    expect(d.verdict).toBe("no_threat_detected");
    expect(d.risk_score).toBe(0);
  });
  it("score is clamped to 100 and the result is deterministic", () => {
    const e = [ev("critical"), ev("critical"), ev("critical")];
    expect(decide(e, ok).risk_score).toBe(100);
    expect(decide(e, ok)).toEqual(decide(e, ok));
  });
  it("banners are exact", () => {
    expect(BANNERS).toEqual({
      malicious: "Don't trust this. Don't click links, open attachments, reply, or pay.",
      suspicious: "Be careful. Verify through a channel you already trust.",
      unknown: "We couldn't fully check this. Treat it with caution.",
      no_threat_detected: "No warning signs found.",
    });
  });
});
