/**
 * Deterministic verdict policy (ported from teger_security_core/policy.py).
 * The verdict is a pure function of evidence and detector coverage. The LLM cannot change it.
 */
import { DetectorReport, Evidence, Verdict } from "./types";

export const POLICY_VERSION = "2026.11.serv-1";
export const MALICIOUS_THRESHOLD = 70;
export const SUSPICIOUS_THRESHOLD = 25;
export const FORCE_MALICIOUS = new Set(["reputation_listed_malicious", "user_blocklisted"]);

export const BANNERS: Record<Verdict, string> = {
  malicious: "Don't trust this. Don't click links, open attachments, reply, or pay.",
  suspicious: "Be careful. Verify through a channel you already trust.",
  unknown: "We couldn't fully check this. Treat it with caution.",
  no_threat_detected: "No warning signs found.",
};

export type Action = "block" | "warn" | "caution" | "allow";

export const ACTION_TEXT: Record<Action, string> = {
  block: "Do not open the link, reply, pay, or enter any information. Report it to your security team and delete it.",
  warn: "Treat this as a likely attack. Do not act on the request; verify it with the sender through a phone number or channel you already trust.",
  caution: "Teger could not fully check this. Do not enter credentials or make payments until you have verified it through a trusted channel.",
  allow: "No threat indicators were found. Stay alert: absence of indicators is not a guarantee of safety.",
};

export interface Decision {
  verdict: Verdict;
  risk_score: number;
  confidence: number;
  action: Action;
  action_text: string;
  banner: string;
  coverage: "complete" | "partial";
  policy_version: string;
}

export function decide(evidence: Evidence[], reports: DetectorReport[]): Decision {
  const score = Math.max(0, Math.min(100, evidence.reduce((s, e) => s + e.weight, 0)));
  const forced = evidence.some((e) => FORCE_MALICIOUS.has(e.category));
  const hasCritical = evidence.some((e) => e.severity === "critical");
  const complete = reports.filter((r) => r.required).every((r) => r.status === "ok");
  const contributing = new Set(evidence.filter((e) => e.weight > 0).map((e) => e.detector)).size;

  let verdict: Verdict;
  let confidence: number;
  if (forced || score >= MALICIOUS_THRESHOLD) {
    verdict = "malicious";
    confidence = forced ? 0.9 : Math.min(0.95, 0.55 + 0.1 * (contributing - 1) + (score - MALICIOUS_THRESHOLD) / 200);
  } else if (score >= SUSPICIOUS_THRESHOLD || hasCritical) {
    verdict = "suspicious";
    confidence = Math.min(0.85, 0.4 + 0.08 * Math.max(0, contributing - 1) + Math.max(0, score - SUSPICIOUS_THRESHOLD) / 250);
  } else if (!complete) {
    verdict = "unknown";
    confidence = 0.2;
  } else {
    verdict = "no_threat_detected";
    confidence = score === 0 ? 0.6 : 0.5;
  }
  const action: Action = ({ malicious: "block", suspicious: "warn", unknown: "caution", no_threat_detected: score === 0 ? "allow" : "caution" } as const)[verdict];
  return {
    verdict,
    risk_score: score,
    confidence: Math.round(confidence * 100) / 100,
    action,
    action_text: ACTION_TEXT[action],
    banner: BANNERS[verdict],
    coverage: complete ? "complete" : "partial",
    policy_version: POLICY_VERSION,
  };
}
