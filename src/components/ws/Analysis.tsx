"use client";
import { useState } from "react";
import type { AgentResult, TraceStep } from "@/lib/agent/agent";
import type { MessageInput } from "@/lib/engine/engine";
import { Mark } from "../Logo";
import { api, VERDICT_LABEL } from "./client";

export interface Item {
  key: string;
  message: MessageInput;
  source: string;
  inboxRef?: string;
  inboxProvider?: string;
  trace: TraceStep[];
  result?: AgentResult;
  running: boolean;
  error?: string;
  model?: string;
  planner?: string;
  savedId?: string;
}

const PHASES = ["observe", "plan", "investigate", "decide", "explain"];
const PHASE_LABEL: Record<string, string> = { observe: "Observe", plan: "Plan", investigate: "Investigate", decide: "Decide", explain: "Explain" };
const SRC: Record<string, string> = { link: "Link check", paste: "Pasted", fixture: "Simulated attack", eml: "Email file", imap: "Inbox (IMAP)", gmail: "Gmail", "gmail-auto": "Gmail · auto-scan" };

export function UserBubble({ item }: { item: Item }) {
  const m = item.message;
  const snippet = (m.body ?? "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 280);
  return (
    <div className="msg user">
      <div className="bubble">
        <div className="meta"><span className="src">{SRC[item.source] ?? item.source}</span>{m.sender && <span>From {m.sender}</span>}</div>
        {m.subject && <div className="subj">{m.subject}</div>}
        <div className="snip">{snippet || "(empty body)"}</div>
      </div>
    </div>
  );
}

export function AgentReply({ item, onLearn, onToast, canDraft = false }: { item: Item; onLearn: (lists: { block: string[]; allow: string[] }) => void; onToast: (s: string) => void; canDraft?: boolean }) {
  const r = item.result;
  const [fb, setFb] = useState("");
  const [labeled, setLabeled] = useState("");
  const [drafted, setDrafted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [json, setJson] = useState(false);
  const reached = new Set<string>(item.trace.map((s) => s.phase));
  const current = item.trace.length ? item.trace[item.trace.length - 1].phase : "observe";

  async function feedback(label: "scam" | "legit") {
    if (!r?.sender_domain) return;
    setBusy(true);
    const { data } = await api<{ ok?: boolean; domain?: string; reason?: string; lists?: { block: string[]; allow: string[] } }>("/api/feedback", { method: "POST", body: JSON.stringify({ domain: r.sender_domain, label }) });
    setBusy(false);
    if (data.lists) onLearn(data.lists);
    if (data.ok) setFb(label === "scam" ? `Teger learned: ${data.domain} is now on your block list. Future messages from it are blocked immediately.` : `Teger learned: ${data.domain} is on your trusted list. Critical signals still override it.`);
    else if (data.reason === "official_domain") setFb("That's an official brand domain, so Teger won't block it from one click. Report the message to your provider instead.");
    else setFb("Couldn't save that feedback.");
  }

  const paymentCase = !!r && r.verdict !== "no_threat_detected" && /\b(iban|bank (details|account)|account number|wire|payment details|remittance|invoice|routing number|sort code)\b/i.test(`${item.message.subject ?? ""} ${item.message.body ?? ""}`);
  async function draft() {
    setBusy(true);
    const { ok, data } = await api<{ error?: string }>("/api/inbox/composio/draft", { method: "POST", body: JSON.stringify({ subject: item.message.subject ?? "", sender: item.message.sender ?? "" }) });
    setBusy(false);
    if (ok) { setDrafted(true); onToast("Verification draft saved in Gmail Drafts. Add a contact you already trust, review, and send it yourself."); } else onToast(data.error ?? "Couldn't create the draft.");
  }

  async function label() {
    if (!item.inboxRef || !r) return;
    const name = r.verdict === "malicious" ? "TEGER_DO_NOT_TRUST" : "TEGER_CAUTION";
    setBusy(true);
    const { ok, data } = await api<{ how?: string; error?: string }>("/api/inbox/label", { method: "POST", body: JSON.stringify({ ref: item.inboxRef, label: name }) });
    setBusy(false);
    if (ok) { setLabeled(name); onToast(`Labeled ${name} in your mailbox`); } else onToast(data.error ?? "Couldn't apply the label.");
  }

  return (
    <div className="msg ai">
      <div className="ai-av"><Mark size={22} /></div>
      <div className="ai-body">
        <div className="ai-name">Teger Agent
          <span className="tag">{item.planner === "fallback" || r?.planner === "fallback" ? "deterministic planner" : `SERV Reasoning${item.model || r?.model ? ` · ${r?.model && r.model !== "none" ? r.model : item.model}` : ""}`}</span>
          {item.running && <span className="spin" />}
        </div>

        {r && (
          <div className={`verdict v-${r.verdict}`}>
            <div className="k">{VERDICT_LABEL[r.verdict]}</div>
            <div className="b">{r.banner}</div>
            <div className="m">Risk {r.risk_score}/100 · confidence {Math.round(r.confidence * 100)}% · coverage {r.coverage} · policy {r.policy_version}</div>
            <div className="meter"><i style={{ width: `${Math.max(3, r.risk_score)}%` }} /></div>
          </div>
        )}
        {item.error && <div className="err">{item.error}</div>}
        {r && <p className="summary">{r.summary}</p>}
        {r?.learned.map((l) => <div className="learned" key={l}><Mark size={18} /> {l}</div>)}
        {r && r.top_reasons.length > 0 && (
          <div className="cards">
            {r.top_reasons.map((x) => (
              <div className={`card s-${x.severity}`} key={x.evidence_id}>
                <div className="h"><span className="sev">{x.severity}</span>{x.title}</div>
                <p>{x.explanation}</p>
                {x.evidence_quote && <blockquote>“{x.evidence_quote}”</blockquote>}
              </div>
            ))}
          </div>
        )}
        {r && (
          <div className="todo">
            <h4>What to do instead</h4>
            <ul>{r.what_to_do.map((s) => <li key={s}>{s}</li>)}</ul>
          </div>
        )}

        <details className="trace" open={item.running || undefined}>
          <summary>
            <span className="phases">{PHASES.map((p) => <i key={p} className={reached.has(p) ? (item.running && p === current ? "on" : "done") : ""} />)}</span>
            <span className="grow">{item.running ? `${PHASE_LABEL[current]}…` : "Agent trace"} · {item.trace.length} step{item.trace.length === 1 ? "" : "s"}</span>
            {r && <span className="hint">{r.usage.serv_calls} SERV call(s) · {r.usage.total_tokens} tokens</span>}
            <span className="chev">›</span>
          </summary>
          <ol className="tl">
            {item.trace.map((s) => (
              <li key={s.n} className={`p-${s.phase}`}>
                <div className="row1">
                  <span className="ph">{PHASE_LABEL[s.phase]}</span>
                  {s.tool && <code>{s.tool}({(s.input ?? "").slice(0, 56)})</code>}
                  <span className={`by ${s.by === "serv" ? "serv" : ""}`}>{s.by === "serv" ? "SERV" : s.by === "teger" ? "engine" : "fallback"}</span>
                  <span className="ms">{s.ms} ms</span>
                </div>
                {s.why && <div className="why">{s.why}</div>}
                <div className="out">{s.output}</div>
                {s.evidence && s.evidence.length > 0 && <div className="evs">{s.evidence.map((e) => <span key={e.id} className={`ev s-${e.severity}`} title={e.description}>{e.category.replace(/_/g, " ")}</span>)}</div>}
              </li>
            ))}
            {item.running && <li className="p-observe" style={{ borderLeftColor: "transparent" }}><span className="typing"><i /><i /><i /></span></li>}
          </ol>
          {r?.planner_note && <div className="note" style={{ margin: "0 14px 12px" }}>{r.planner_note}</div>}
        </details>

        {r && (
          <>
            <div className="actions">
              <span>Was this right?{r.sender_domain ? ` Teach Teger about ${r.sender_domain}:` : ""}</span>
              <button className="btn danger sm" disabled={busy || !r.sender_domain} onClick={() => feedback("scam")}>Confirm scam</button>
              <button className="btn ghost sm" disabled={busy || !r.sender_domain} onClick={() => feedback("legit")}>It&apos;s legit</button>
              {item.inboxRef && (r.verdict === "malicious" || r.verdict === "suspicious") && (
                <button className="btn ghost sm" disabled={busy || !!labeled} onClick={label}>{labeled ? `✓ Labeled ${labeled}` : `Label ${r.verdict === "malicious" ? "TEGER_DO_NOT_TRUST" : "TEGER_CAUTION"} in mailbox`}</button>
              )}
              {item.inboxRef && canDraft && paymentCase && (
                <button className="btn ghost sm" disabled={busy || drafted} onClick={draft}>{drafted ? "✓ Draft saved" : "Create verification draft"}</button>
              )}
              <button className="linkbtn" onClick={() => setJson(!json)}>{json ? "Hide" : "Show"} JSON</button>
            </div>
            {fb && <div className="learned"><Mark size={18} /> {fb}</div>}
            {r.screenshots.filter((s) => s.status !== "ok").length > 0 && <div className="note">Screenshot unavailable for {r.screenshots.map((s) => new URL(s.url).host).join(", ")}. The link was never opened on your device.</div>}
            {json && <pre className="json">{JSON.stringify({ verdict: r.verdict, banner: r.banner, risk_score: r.risk_score, top_reasons: r.top_reasons, what_to_do: r.what_to_do, learned: r.learned, model: r.model, planner: r.planner, usage: r.usage, trace: r.trace }, null, 2)}</pre>}
          </>
        )}
      </div>
    </div>
  );
}
