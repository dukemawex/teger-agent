/** Teger deterministic engine: runs local detectors over a message. */
import { advancedDetector } from "./advanced";
import { brandDetector } from "./brand";
import { applyRules, CREDENTIAL_RULES, SOCIAL_RULES } from "./language";
import { extractUrls, ParsedUrl } from "./urls";
import { urlHeuristics } from "./urlHeuristics";
import { DetectorReport, Evidence, FindingCollector, SEVERITY_WEIGHT } from "./types";

export interface MessageInput {
  sender?: string;
  reply_to?: string;
  subject?: string;
  body?: string;
  headers?: string;
}

export interface EngineRun {
  detector: string;
  report: DetectorReport;
  evidence: Omit<Evidence, "id">[];
}

/** Plain text view of the message: strip HTML tags and zero-width chars, decode a few entities. */
export function visibleText(s: string): string {
  return s
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/[\u200b-\u200f\u2060-\u2064\ufeff]/g, "")
    .replace(/[ \t]+/g, " ");
}

function run(detector: string, required: boolean, fn: (c: FindingCollector) => void): EngineRun {
  const c = new FindingCollector();
  try {
    fn(c);
  } catch (e) {
    // A crashing detector reduces coverage; it must not read as "clean".
    return { detector, report: { name: detector, status: "error", required, detail: "Detector failed." }, evidence: [] };
  }
  return {
    detector,
    report: { name: detector, status: "ok", required },
    evidence: c.findings.map((f) => ({
      detector, category: f.category, tactic: f.tactic, severity: f.severity,
      weight: f.weight ?? SEVERITY_WEIGHT[f.severity], description: f.description.slice(0, 500), indicator: f.indicator?.slice(0, 300),
    })),
  };
}

export function analyzeMessage(m: MessageInput): { runs: EngineRun[]; urls: ParsedUrl[]; text: string } {
  const raw = `${m.subject ?? ""}\n${m.body ?? ""}`;
  const text = visibleText(raw);
  const urls = extractUrls(`${m.body ?? ""}`.replace(/href=["']([^"']+)["']/gi, " $1 "));
  const sender = m.sender ?? "";
  const runs = [
    run("url_heuristics", urls.length > 0, (c) => urls.forEach((u) => urlHeuristics(u, c))),
    run("brand_impersonation", !!(urls.length || sender), (c) => brandDetector(urls, sender, text, c)),
    run("credential_harvesting", !!text.trim(), (c) => applyRules(CREDENTIAL_RULES, text, c)),
    run("social_engineering", !!text.trim(), (c) => applyRules(SOCIAL_RULES, text, c)),
    run("advanced_social_engineering", !!text.trim(), (c) => advancedDetector(sender, text, raw, c)),
  ];
  return { runs, urls, text };
}
