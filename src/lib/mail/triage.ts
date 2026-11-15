/** Fast, offline, deterministic pre-screen for inbox lists (no network, no model). */
import { analyzeMessage, MessageInput } from "../engine/engine";
import { decide } from "../engine/policy";
import type { Evidence } from "../engine/types";

export interface Triage { verdict: "malicious" | "suspicious" | "no_threat_detected"; risk: number; top?: string }

export function triage(m: MessageInput): Triage {
  const { runs } = analyzeMessage(m);
  const evidence = runs.flatMap((r) => r.evidence).map((e, i) => ({ ...e, id: `t${i}` })) as Evidence[];
  const d = decide(evidence, runs.map((r) => ({ ...r.report, required: false })));
  const verdict = d.verdict === "malicious" ? "malicious" : d.verdict === "suspicious" ? "suspicious" : "no_threat_detected";
  const top = [...evidence].sort((a, b) => b.weight - a.weight)[0];
  return { verdict, risk: d.risk_score, top: verdict === "no_threat_detected" ? undefined : top?.category.replace(/_/g, " ") };
}
