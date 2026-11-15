export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Verdict = "malicious" | "suspicious" | "unknown" | "no_threat_detected";

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  info: 0,
  low: 8,
  medium: 18,
  high: 35,
  critical: 60,
};

export interface Evidence {
  id: string;
  detector: string;
  category: string;
  tactic: string;
  severity: Severity;
  weight: number;
  description: string;
  /** Short redacted quote / indicator from the message that triggered the finding. */
  indicator?: string;
}

export interface DetectorReport {
  name: string;
  status: "ok" | "skipped" | "unavailable" | "error";
  required: boolean;
  detail?: string;
}

export interface Finding {
  category: string;
  severity: Severity;
  description: string;
  indicator?: string;
  tactic: string;
  weight?: number;
}

export class FindingCollector {
  findings: Finding[] = [];
  private seen = new Set<string>();
  add(f: Finding) {
    if (this.seen.has(f.category)) return;
    this.seen.add(f.category);
    this.findings.push(f);
  }
}
