/**
 * Agent tools. Each wraps Teger's deterministic engine or an SSRF-safe network
 * lookup. Tools add evidence to the run state directly; the model only sees
 * summaries and can never inject or remove evidence.
 */
import { BRANDS, brandForDomain, isOfficialDomain } from "../engine/brands";
import { inspectHost } from "../engine/brand";
import { analyzeMessage, MessageInput } from "../engine/engine";
import { decide, Decision } from "../engine/policy";
import { checkSenderAuth } from "../engine/senderAuth";
import { DetectorReport, Evidence, FindingCollector, SEVERITY_WEIGHT } from "../engine/types";
import { extractUrls, parseUrl, ParsedUrl, registrableDomain, senderDomain } from "../engine/urls";
import { urlHeuristics } from "../engine/urlHeuristics";
import { UserLists } from "./memory";
import { BlockedTargetError, Net } from "./net";

export interface AgentState {
  message: MessageInput;
  evidence: Evidence[];
  reports: DetectorReport[];
  urls: ParsedUrl[];
  allowedDomains: Set<string>;
  lists: UserLists;
  learned: string[];
  decision?: Decision;
  screenshots: { url: string; image?: string; status: string }[];
  sources: { title: string; url: string }[];
  ran: Set<string>;
}

export interface ToolEnv {
  net: Net;
  env: Record<string, string | undefined>;
}

export function initState(message: MessageInput, lists: UserLists): AgentState {
  const urls = extractUrls(`${message.body ?? ""}`.replace(/href=["']([^"']+)["']/gi, " $1 "));
  const allowed = new Set<string>();
  const add = (d?: string) => { if (d) { allowed.add(d.toLowerCase()); const r = registrableDomain(d); if (r) allowed.add(r); } };
  add(senderDomain(message.sender));
  add(senderDomain(message.reply_to));
  urls.forEach((u) => add(u.host));
  for (const m of `${message.body ?? ""}`.matchAll(/[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/g)) add(m[1]);
  return { message, evidence: [], reports: [], urls, allowedDomains: allowed, lists, learned: [], screenshots: [], sources: [], ran: new Set() };
}

function addEvidence(state: AgentState, items: Omit<Evidence, "id">[]): Evidence[] {
  const added: Evidence[] = [];
  for (const it of items) {
    if (state.evidence.some((e) => e.category === it.category)) continue;
    const ev = { ...it, id: `ev-${state.evidence.length + 1}` };
    state.evidence.push(ev);
    added.push(ev);
  }
  return added;
}

function upsertReport(state: AgentState, r: DetectorReport) {
  state.reports = state.reports.filter((x) => x.name !== r.name).concat(r);
}

function collectorToEvidence(detector: string, c: FindingCollector): Omit<Evidence, "id">[] {
  return c.findings.map((f) => ({ detector, category: f.category, tactic: f.tactic, severity: f.severity, weight: f.weight ?? SEVERITY_WEIGHT[f.severity], description: f.description, indicator: f.indicator }));
}

const brief = (e: Evidence) => ({ id: e.id, category: e.category, severity: e.severity, finding: e.description, quote: e.indicator });

const WHY = { why: { type: "string", description: "One sentence: why you are calling this tool now (shown in the audit trail)." } };

export const TOOL_SCHEMAS = [
  { type: "function" as const, function: { name: "analyze_message", description: "Run Teger's deterministic detectors (language, brand, URL, homoglyph, deadline, takeover, OAuth, secret-request, prompt-injection) over the submitted message. Fields are always read from the original submitted message; values you pass are only used to confirm which message you mean.", parameters: { type: "object", properties: { ...WHY, sender: { type: "string" }, reply_to: { type: "string" }, subject: { type: "string" }, body: { type: "string", description: "Leave empty; the original body is used." } }, required: ["why"] } } },
  { type: "function" as const, function: { name: "check_sender_auth", description: "Check SPF/DKIM/DMARC results and From vs Reply-To mismatch from the message headers.", parameters: { type: "object", properties: { ...WHY, headers: { type: "string", description: "Leave empty; the original headers are used." } }, required: ["why"] } } },
  { type: "function" as const, function: { name: "inspect_domain", description: "Inspect a domain that appears in the message: registration age via RDAP and look-alike/homoglyph comparison with known brands. Only domains present in the message are allowed.", parameters: { type: "object", properties: { ...WHY, domain: { type: "string" } }, required: ["why", "domain"] } } },
  { type: "function" as const, function: { name: "inspect_link", description: "Resolve a link from the message server-side (SSRF-safe, no private IPs, size/time limited): redirect chain, final domain, page title, login forms. Only links present in the message are allowed.", parameters: { type: "object", properties: { ...WHY, url: { type: "string" } }, required: ["why", "url"] } } },
  { type: "function" as const, function: { name: "research_brand", description: "Look up the official domains of a brand the message claims to be from and whether a given domain belongs to it.", parameters: { type: "object", properties: { ...WHY, brand: { type: "string" }, link_domain: { type: "string" } }, required: ["why", "brand"] } } },
  { type: "function" as const, function: { name: "preview_site", description: "Take an isolated remote screenshot of a link from the message (Instabox). Use only if the link is central to the decision.", parameters: { type: "object", properties: { ...WHY, url: { type: "string" } }, required: ["why", "url"] } } },
  { type: "function" as const, function: { name: "decide", description: "Apply Teger's deterministic policy to ALL evidence gathered so far (plus the user's learned allow/block list). Returns the final verdict. You cannot change it. Call exactly once, after investigating.", parameters: { type: "object", properties: { ...WHY }, required: ["why"] } } },
];

export type ToolName = "analyze_message" | "check_sender_auth" | "inspect_domain" | "inspect_link" | "research_brand" | "preview_site" | "decide";

export interface ToolResult {
  summary: string;
  output: Record<string, unknown>;
  evidence_added: Evidence[];
}

export async function runTool(name: string, args: Record<string, unknown>, state: AgentState, te: ToolEnv): Promise<ToolResult> {
  state.ran.add(name);
  switch (name) {
    case "analyze_message": return analyzeTool(state);
    case "check_sender_auth": return senderAuthTool(state);
    case "inspect_domain": return inspectDomainTool(String(args.domain ?? ""), state, te);
    case "inspect_link": return inspectLinkTool(String(args.url ?? ""), state, te);
    case "research_brand": return researchBrandTool(String(args.brand ?? ""), args.link_domain ? String(args.link_domain) : undefined, state, te);
    case "preview_site": return previewTool(String(args.url ?? ""), state, te);
    case "decide": return decideTool(state);
    default: return { summary: `Unknown tool ${name}`, output: { error: "unknown_tool" }, evidence_added: [] };
  }
}

function analyzeTool(state: AgentState): ToolResult {
  const { runs } = analyzeMessage(state.message);
  const added: Evidence[] = [];
  for (const r of runs) {
    upsertReport(state, r.report);
    added.push(...addEvidence(state, r.evidence));
  }
  return {
    summary: added.length ? `${added.length} finding(s): ${added.map((e) => e.category).join(", ")}` : "No findings from local detectors.",
    output: { detectors: runs.map((r) => ({ name: r.detector, status: r.report.status, findings: r.evidence.length })), findings: added.map(brief), links: state.urls.map((u) => u.href), domains: [...state.allowedDomains] },
    evidence_added: added,
  };
}

function senderAuthTool(state: AgentState): ToolResult {
  const c = new FindingCollector();
  const res = checkSenderAuth(state.message.headers ?? "", state.message.sender ?? "", state.message.reply_to, c);
  upsertReport(state, { name: "sender_auth", status: res.headers_present || state.message.reply_to ? "ok" : "skipped", required: false, detail: res.headers_present ? undefined : "No headers supplied." });
  const added = addEvidence(state, collectorToEvidence("sender_auth", c));
  return {
    summary: `${res.headers_present ? `SPF=${res.spf ?? "n/a"} DKIM=${res.dkim ?? "n/a"} DMARC=${res.dmarc ?? "n/a"}` : "No headers supplied"}${res.reply_to_domain ? `; Reply-To @${res.reply_to_domain}` : ""}${added.length ? ` → ${added.map((e) => e.category).join(", ")}` : ""}`,
    output: { ...res, findings: added.map(brief) },
    evidence_added: added,
  };
}

async function inspectDomainTool(domainArg: string, state: AgentState, te: ToolEnv): Promise<ToolResult> {
  const domain = domainArg.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0];
  const reg = registrableDomain(domain) ?? domain;
  if (!state.allowedDomains.has(domain) && !state.allowedDomains.has(reg)) {
    return { summary: `Refused: ${domain} does not appear in the message.`, output: { error: "domain_not_in_message" }, evidence_added: [] };
  }
  const c = new FindingCollector();
  inspectHost(domain, "", c);
  const official = isOfficialDomain(reg);
  let ageDays: number | undefined;
  let registered: string | undefined;
  let rdapStatus = "unavailable";
  try {
    const tld = reg.split(".").pop();
    const endpoints = [`https://rdap.org/domain/${encodeURIComponent(reg)}`];
    if (tld === "com" || tld === "net") endpoints.unshift(`https://rdap.verisign.com/${tld}/v1/domain/${encodeURIComponent(reg)}`);
    let data: { events?: { eventAction: string; eventDate: string }[] } | undefined;
    let lastErr: unknown;
    for (const ep of endpoints) {
      try { data = (await te.net.fetchJson(ep, { headers: { accept: "application/rdap+json, application/json" } }, 5000)) as typeof data; break; }
      catch (e) { lastErr = e; if (/HTTP 404/.test(String((e as Error).message))) { rdapStatus = "not_found"; break; } }
    }
    if (!data) throw lastErr ?? new Error("no data");
    const ev = data.events?.find((e) => e.eventAction === "registration");
    rdapStatus = "ok";
    if (ev) {
      registered = ev.eventDate;
      ageDays = Math.floor((Date.now() - Date.parse(ev.eventDate)) / 86400000);
      if (!official && ageDays < 30) c.add({ category: "newly_registered_domain", severity: "high", tactic: "link_manipulation", description: `${reg} was registered only ${ageDays} day(s) ago.`, indicator: `${reg} registered ${ev.eventDate.slice(0, 10)}` });
      else if (!official && ageDays < 180) c.add({ category: "young_domain", severity: "medium", tactic: "link_manipulation", description: `${reg} is less than 6 months old (${ageDays} days).`, indicator: `${reg} registered ${ev.eventDate.slice(0, 10)}` });
    }
  } catch (e) {
    if (rdapStatus !== "not_found") rdapStatus = `unavailable (${String((e as Error)?.message ?? e).slice(0, 40)})`;
  }
  upsertReport(state, { name: `domain:${reg}`, status: "ok", required: false, detail: `RDAP ${rdapStatus}` });
  const added = addEvidence(state, collectorToEvidence("domain_intel", c));
  const brand = brandForDomain(reg);
  return {
    summary: `${reg}: ${official ? `official ${brand?.name} domain` : "not a known brand domain"}; age ${ageDays !== undefined ? `${ageDays} days` : rdapStatus === "not_found" ? "unknown (no RDAP registration record found)" : `unknown (RDAP ${rdapStatus})`}${added.length ? ` → ${added.map((e) => e.category).join(", ")}` : ""}`,
    output: { domain, registrable: reg, official_brand_domain: official, brand: brand?.name, registered, age_days: ageDays, rdap: rdapStatus, findings: added.map(brief) },
    evidence_added: added,
  };
}

function pageFacts(html: string) {
  const title = html.match(/<title[^>]*>([\s\S]{0,200}?)<\/title>/i)?.[1]?.replace(/\s+/g, " ").trim();
  const hasPassword = /<input[^>]+type=["']?password/i.test(html);
  const formActions = [...html.matchAll(/<form[^>]+action=["']([^"']+)["']/gi)].map((m) => m[1]).slice(0, 5);
  return { title, hasPassword, formActions };
}

async function inspectLinkTool(urlArg: string, state: AgentState, te: ToolEnv): Promise<ToolResult> {
  const parsed = parseUrl(urlArg);
  if (!parsed || !state.urls.some((u) => u.href === parsed.href || u.host === parsed.host)) {
    return { summary: `Refused: that link does not appear in the message.`, output: { error: "link_not_in_message" }, evidence_added: [] };
  }
  const c = new FindingCollector();
  urlHeuristics(parsed, c);
  inspectHost(parsed.host, parsed.path, c, parsed.unicodeHost ?? parsed.host);
  let fetchStatus = "not_fetched";
  let output: Record<string, unknown> = {};
  try {
    const r = await te.net.safeFetch(parsed.href, { maxHops: 5, maxBytes: 200_000, timeoutMs: 6000 });
    fetchStatus = "ok";
    const final = parseUrl(r.finalUrl);
    const facts = /html/i.test(r.contentType ?? "") ? pageFacts(r.body) : { title: undefined, hasPassword: false, formActions: [] };
    if (final && final.registrableDomain !== parsed.registrableDomain) {
      c.add({ category: "redirect_to_other_domain", severity: "medium", tactic: "link_manipulation", description: `The link silently redirects to a different domain (${final.host}).`, indicator: r.hops.map((h) => new URL(h.url).host).concat(final.host).join(" → ") });
      urlHeuristics(final, c);
      inspectHost(final.host, final.path, c, final.unicodeHost ?? final.host);
    }
    const finalReg = final?.registrableDomain;
    if (facts.hasPassword && !isOfficialDomain(finalReg)) c.add({ category: "credential_form_on_untrusted_domain", severity: "high", tactic: "credential_harvesting", description: `The landing page asks for a password on ${final?.host}, which is not a known brand domain.`, indicator: facts.title ?? final?.host });
    if (facts.title) {
      const b = BRANDS.find((b) => new RegExp(`\\b${b.name}\\b`, "i").test(facts.title!));
      if (b && !b.domains.includes(finalReg ?? "")) c.add({ category: "brand_page_on_untrusted_domain", severity: "high", tactic: "trust_transfer", description: `The page title claims to be ${b.name}, but it is hosted on ${final?.host}.`, indicator: facts.title });
    }
    output = { hops: r.hops, final_url: r.finalUrl, status: r.status, title: facts.title, password_field: facts.hasPassword, truncated: r.truncated };
  } catch (e) {
    fetchStatus = e instanceof BlockedTargetError ? `blocked: ${e.message}` : `unreachable (${(e as Error).message?.slice(0, 80) || "error"})`;
  }
  upsertReport(state, { name: `link:${parsed.host}`, status: "ok", required: false, detail: `fetch ${fetchStatus}` });
  const added = addEvidence(state, collectorToEvidence("link_intel", c));
  return {
    summary: `${parsed.host}: fetch ${fetchStatus}${output.final_url ? ` → ${new URL(String(output.final_url)).host}` : ""}${added.length ? `; ${added.map((e) => e.category).join(", ")}` : ""}`,
    output: { url: parsed.href, fetch: fetchStatus, ...output, findings: added.map(brief) },
    evidence_added: added,
  };
}

async function researchBrandTool(brandArg: string, linkDomain: string | undefined, state: AgentState, te: ToolEnv): Promise<ToolResult> {
  const known = BRANDS.find((b) => b.name.toLowerCase() === brandArg.toLowerCase() || b.keywords.includes(brandArg.toLowerCase()));
  const reg = linkDomain ? registrableDomain(linkDomain.toLowerCase()) ?? linkDomain.toLowerCase() : undefined;
  const out: Record<string, unknown> = { brand: brandArg, reference_list: known ? known.domains : null };
  let source = "teger-reference-list";
  if (te.env.PARALLEL_API_KEY) {
    try {
      const data = (await te.net.fetchJson("https://api.parallel.ai/v1beta/search", {
        method: "POST",
        headers: { "x-api-key": te.env.PARALLEL_API_KEY, "content-type": "application/json" },
        body: JSON.stringify({ objective: `Official website and support email domains of ${brandArg.slice(0, 60)}`, max_results: 3 }),
      }, 8000)) as { results?: { url: string; title?: string }[] };
      const results = (data.results ?? []).slice(0, 3).map((r) => ({ title: r.title ?? r.url, url: r.url }));
      state.sources.push(...results);
      out.web_sources = results;
      source = "parallel-search + teger-reference-list";
    } catch (e) {
      out.web_search = `unavailable (${(e as Error).message.slice(0, 60)})`;
    }
  } else {
    out.web_search = "unavailable (PARALLEL_API_KEY not configured); used Teger's reviewed brand list";
  }
  const c = new FindingCollector();
  if (known && reg && !known.domains.includes(reg)) {
    c.add({ category: "domain_not_official_for_brand", severity: "medium", tactic: "trust_transfer", description: `${reg} is not one of ${known.name}'s official domains (${known.domains.slice(0, 3).join(", ")}).`, indicator: reg });
  }
  const added = addEvidence(state, collectorToEvidence("brand_research", c));
  return {
    summary: known ? `${known.name} official domains: ${known.domains.slice(0, 4).join(", ")}${reg ? `; ${reg} is ${known.domains.includes(reg) ? "official" : "NOT official"}` : ""} (${source})` : `${brandArg}: not in reference list (${source})`,
    output: { ...out, link_domain: reg, is_official: known && reg ? known.domains.includes(reg) : null, source, findings: added.map(brief) },
    evidence_added: added,
  };
}

async function previewTool(urlArg: string, state: AgentState, te: ToolEnv): Promise<ToolResult> {
  const parsed = parseUrl(urlArg);
  if (!parsed || !state.urls.some((u) => u.host === parsed.host)) return { summary: "Refused: link not in message.", output: { error: "link_not_in_message" }, evidence_added: [] };
  if (!te.env.INSTABOX_API_KEY || !te.env.INSTABOX_SCREENSHOT_URL) {
    state.screenshots.push({ url: parsed.href, status: "unavailable" });
    return { summary: "Screenshot unavailable (Instabox not configured). Link was not opened on any user device.", output: { status: "unavailable" }, evidence_added: [] };
  }
  try {
    const data = (await te.net.fetchJson(te.env.INSTABOX_SCREENSHOT_URL, { method: "POST", headers: { authorization: `Bearer ${te.env.INSTABOX_API_KEY}`, "content-type": "application/json" }, body: JSON.stringify({ url: parsed.href }) }, 20000)) as { image?: string; screenshot_url?: string };
    const image = data.image ?? data.screenshot_url;
    state.screenshots.push({ url: parsed.href, image, status: image ? "ok" : "empty" });
    return { summary: image ? "Captured isolated screenshot." : "Screenshot service returned no image.", output: { status: image ? "ok" : "empty" }, evidence_added: [] };
  } catch (e) {
    state.screenshots.push({ url: parsed.href, status: "error" });
    return { summary: `Screenshot failed (${(e as Error).message.slice(0, 60)}).`, output: { status: "error" }, evidence_added: [] };
  }
}

/** Apply learned allow/block lists, then the deterministic policy. */
export function decideTool(state: AgentState): ToolResult {
  if (!state.ran.has("analyze_message")) analyzeTool(state); // the verdict always includes the local detectors
  const sd = senderDomain(state.message.sender);
  // No sender (e.g. a pasted link): the first link's domain is what the user taught Teger about.
  const sreg = sd ? registrableDomain(sd) : state.urls[0]?.registrableDomain;
  const linkRegs = state.urls.map((u) => u.registrableDomain).filter(Boolean) as string[];
  const blockedHit = [sd, sreg, ...linkRegs].find((d) => d && state.lists.block.includes(d));
  const learnedAdded: Evidence[] = [];
  if (blockedHit) {
    learnedAdded.push(...addEvidence(state, [{ detector: "feedback_memory", category: "user_blocklisted", tactic: "learned", severity: "critical", weight: SEVERITY_WEIGHT.critical, description: `You previously confirmed ${blockedHit} as a scam. Teger blocks it on sight.`, indicator: blockedHit }]));
    state.learned.push(`Teger learned: ${blockedHit} is on your block list (you confirmed a scam from it), so it is blocked immediately.`);
  } else if (sreg && state.lists.allow.includes(sreg)) {
    const hasCritical = state.evidence.some((e) => e.severity === "critical");
    learnedAdded.push(...addEvidence(state, [{ detector: "feedback_memory", category: "user_allowlisted", tactic: "learned", severity: "info", weight: hasCritical ? 0 : -30, description: `You previously marked ${sreg} as legitimate.${hasCritical ? " A critical signal is present, so the trust mark does not lower the risk." : " Its risk is lowered (critical signals still override)."}`, indicator: sreg }]));
    state.learned.push(`Teger learned: you marked ${sreg} as legitimate before${hasCritical ? ", but a critical signal overrides that trust" : ", so its risk was lowered"}.`);
  }
  state.decision = decide(state.evidence, state.reports);
  const d = state.decision;
  return {
    summary: `Verdict ${d.verdict.toUpperCase()} (risk ${d.risk_score}/100, confidence ${Math.round(d.confidence * 100)}%, coverage ${d.coverage})`,
    output: { verdict: d.verdict, risk_score: d.risk_score, confidence: d.confidence, banner: d.banner, policy_version: d.policy_version, evidence: state.evidence.map(brief) },
    evidence_added: learnedAdded,
  };
}
