"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { SAMPLE_LINKS, type Fixture } from "@/lib/fixtures";
import type { MessageInput } from "@/lib/engine/engine";
import { Logo, Mark, Pixels } from "../Logo";
import { AgentReply, Item, UserBubble } from "./Analysis";
import { InboxDrawer, Me, SettingsDrawer } from "./Drawers";
import { api, guestId, looksLikeLinkOnly, looksLikeRawEmail, streamAgent, VERDICT_LABEL } from "./client";

interface HistItem { id: string; createdAt: string; source: string; subject: string; sender: string; verdict: string; risk: number }

const NOTICES: Record<string, string> = {
  google_not_configured: "Google sign-in isn't configured on this deployment yet.",
  oauth_failed: "Google sign-in didn't complete. Please try again.",
  gmail_connected: "Gmail connected. Open Inbox to scan messages.",
  composio_not_configured: "Gmail via Composio isn't configured on this deployment yet (COMPOSIO_API_KEY). Use IMAP or an .eml file for now.",
  composio_failed: "Gmail wasn't connected. The Composio consent didn't complete; please try again.",
  composio_permissions: "Composio refused to create the Gmail link: this deployment's COMPOSIO_API_KEY is missing permissions (Session management, Connected accounts and Tool execution need write access).",
  composio_error: "Couldn't reach Composio to connect Gmail. Please try again in a moment.",
  busy: "Too many attempts. Wait a minute and try again.",
  gmail_scopes_missing: "Gmail wasn't connected: the required permissions weren't approved.",
  signed_in: "Signed in with Google.",
  signin_required: "Sign in first, then connect Gmail.",
  email_unverified: "That Google account's email isn't verified.",
};

export default function Workspace({ fixtures }: { fixtures: Fixture[] }) {
  const router = useRouter();
  const params = useSearchParams();
  const [me, setMe] = useState<Me | null>(null);
  const [items, setItems] = useState<Item[]>([]);
  const [history, setHistory] = useState<HistItem[]>([]);
  const [activeHist, setActiveHist] = useState<string>("");
  const [text, setText] = useState("");
  const [fields, setFields] = useState({ sender: "", reply_to: "", subject: "", headers: "" });
  const [showFields, setShowFields] = useState(false);
  const [drawer, setDrawer] = useState<"" | "inbox" | "settings">("");
  const [sbOpen, setSbOpen] = useState(false);
  const [toast, setToast] = useState("");
  const [theme, setThemeState] = useState("light");
  const running = items.some((i) => i.running);
  const threadRef = useRef<HTMLDivElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const autoRan = useRef(false);

  const notify = useCallback((s: string) => { setToast(s); setTimeout(() => setToast(""), 3800); }, []);
  const refreshMe = useCallback(async () => { const { data } = await api<Me>("/api/me"); setMe(data); }, []);
  const refreshHistory = useCallback(async () => { const { data } = await api<{ items: HistItem[] }>("/api/history"); setHistory(data.items ?? []); }, []);

  useEffect(() => {
    guestId();
    setThemeState(document.documentElement.dataset.theme || "light");
    refreshMe(); refreshHistory();
    const n = params.get("notice");
    if (n && NOTICES[n]) notify(NOTICES[n]);
    if (n === "gmail_connected" || params.get("connect") === "1") setDrawer("inbox");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Auto-scan feed: poll history while Composio auto-scan is on.
  useEffect(() => {
    if (!me?.inbox?.autoScan) return;
    const t = setInterval(refreshHistory, 20_000);
    return () => clearInterval(t);
  }, [me?.inbox?.autoScan, refreshHistory]);

  useEffect(() => { if (items.length) threadRef.current?.scrollTo({ top: threadRef.current.scrollHeight }); }, [items]);

  const setTheme = (t: string) => { document.documentElement.dataset.theme = t; localStorage.setItem("teger_theme", t); setThemeState(t); };

  const update = (key: string, f: (i: Item) => Item) => setItems((xs) => xs.map((x) => (x.key === key ? f(x) : x)));

  async function analyze(message: MessageInput, source: string, inbox?: { ref: string; provider: string }) {
    if (running) return;
    const key = Math.random().toString(36).slice(2);
    setActiveHist("");
    setItems((xs) => [...xs, { key, message, source, inboxRef: inbox?.ref, inboxProvider: inbox?.provider, trace: [], running: true }]);
    setSbOpen(false);
    try {
      const res = await streamAgent({ message, source, inboxRef: inbox?.ref }, (ev) => {
        if (ev.type === "start") update(key, (i) => ({ ...i, model: ev.model, planner: ev.planner }));
        if (ev.type === "step") update(key, (i) => ({ ...i, trace: [...i.trace, ev.step] }));
        if (ev.type === "final") update(key, (i) => ({ ...i, result: ev.result }));
        if (ev.type === "error") update(key, (i) => ({ ...i, error: ev.message }));
        if (ev.type === "saved") { update(key, (i) => ({ ...i, savedId: ev.id })); setActiveHist(ev.id); }
      });
      if (!res.ok) update(key, (i) => ({ ...i, error: res.status === 429 ? "You're going fast. Wait a few seconds and try again." : "Couldn't run the agent. Check the message and try again." }));
    } catch {
      update(key, (i) => ({ ...i, error: "Connection lost while the agent was working. Try again." }));
    } finally {
      update(key, (i) => ({ ...i, running: false }));
      refreshHistory();
    }
  }

  useEffect(() => {
    const sim = params.get("simulate");
    const link = params.get("link")?.trim().slice(0, 2000);
    if (me && !autoRan.current) {
      const f = sim ? fixtures.find((x) => x.id === sim) : undefined;
      if (f) { autoRan.current = true; analyze(f.message, "fixture"); }
      else if (link) { autoRan.current = true; analyze({ body: link }, looksLikeLinkOnly(link) ? "link" : "paste"); }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [me]);

  async function send() {
    const t = text.trim();
    if (!t && !fields.subject.trim()) return;
    let message: MessageInput = { ...fields, body: t };
    let source = !fields.sender.trim() && !fields.subject.trim() && !fields.headers.trim() && looksLikeLinkOnly(t) ? "link" : "paste";
    if (looksLikeRawEmail(t)) {
      const { ok, data } = await api<{ message: MessageInput }>("/api/parse-email", { method: "POST", body: JSON.stringify({ raw: t }) });
      if (ok) { message = data.message; source = "eml"; }
    }
    setText(""); setFields({ sender: "", reply_to: "", subject: "", headers: "" }); setShowFields(false);
    analyze(message, source);
  }

  async function onFile(f: File) {
    if (f.size > 2_500_000) { notify("That file is too large (max 2.5 MB)."); return; }
    const raw = await f.text();
    const { ok, data } = await api<{ message: MessageInput; error?: string }>("/api/parse-email", { method: "POST", body: JSON.stringify({ raw }) });
    if (!ok) { notify((data as { error?: string }).error ?? "Couldn't read that email file."); return; }
    analyze(data.message, "eml");
  }

  async function scanInbox(m: { ref: string; subject: string }) {
    setDrawer("");
    notify(`Fetching “${m.subject.slice(0, 40)}”…`);
    const { ok, data } = await api<{ message: MessageInput; provider: string; error?: string }>(`/api/inbox/message?ref=${encodeURIComponent(m.ref)}`);
    if (!ok) { notify(data.error ?? "Couldn't fetch that message."); return; }
    analyze(data.message, data.provider, { ref: m.ref, provider: data.provider });
  }

  async function openHistory(h: HistItem) {
    setSbOpen(false);
    const { ok, data } = await api<{ message: MessageInput; result: Item["result"]; source: string; inbox?: { ref: string; provider: string } }>(`/api/history/${h.id}`);
    if (!ok || !data.result) { notify("That analysis has expired."); return; }
    setActiveHist(h.id);
    setItems([{ key: h.id, message: data.message, source: data.source, inboxRef: data.inbox?.ref, inboxProvider: data.inbox?.provider, trace: data.result.trace, result: data.result, running: false, savedId: h.id }]);
  }

  async function signOut() {
    await api("/api/auth/logout", { method: "POST" });
    setDrawer(""); setItems([]);
    await refreshMe(); await refreshHistory();
    router.refresh();
  }

  const newChat = () => { setItems([]); setActiveHist(""); setSbOpen(false); };

  return (
    <div className="ws">
      {sbOpen && <div className="scrim" onClick={() => setSbOpen(false)} />}
      <aside className={`sb ${sbOpen ? "open" : ""}`}>
        <div className="sb-top"><Logo href="/" /></div>
        <button className="btn ghost new" onClick={newChat}>＋ New analysis</button>
        <div className="sb-sec"><span>History</span>{history.length > 0 && <span>{history.length}</span>}</div>
        <div className="sb-list">
          {history.length === 0 && <p className="hint" style={{ padding: "4px 10px" }}>Your analyses will appear here.</p>}
          {history.map((h) => (
            <button key={h.id} className={`hist ${activeHist === h.id ? "on" : ""}`} onClick={() => openHistory(h)} title={h.subject}>
              <i className={`dot ${h.verdict}`} />
              <div><span className="t">{h.subject}</span><span className="s">{VERDICT_LABEL[h.verdict]} · {new Date(h.createdAt).toLocaleDateString(undefined, { month: "short", day: "numeric" })} {new Date(h.createdAt).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}</span></div>
            </button>
          ))}
        </div>
        <div className="sb-bottom">
          <button className="sb-item" onClick={() => setDrawer("inbox")}><span className={`status-dot ${me?.inbox ? "on" : ""}`} /> Inbox <span className="sub">{me?.inbox ? me.inbox.account : me?.user ? "Connect" : "Sign in"}</span></button>
          <button className="sb-item" onClick={() => setDrawer("settings")}>⚙ Settings <span className="sub">{me ? `${me.lists.block.length} blocked · ${me.lists.allow.length} trusted` : ""}</span></button>
          {me?.user ? (
            <button className="sb-item" onClick={() => setDrawer("settings")}><span className="ai-av" style={{ width: 24, height: 24, borderRadius: 6, color: "var(--bg)", fontSize: 12, fontWeight: 700 }}>{me.user.name[0]?.toUpperCase()}</span> {me.user.name}</button>
          ) : (
            <a className="sb-item" href="/signin?next=/app" style={{ textDecoration: "none" }}>→ Sign in <span className="sub">Guest mode</span></a>
          )}
        </div>
      </aside>

      <main className="main">
        <div className="mtop">
          <button className="btn ghost icon burger" onClick={() => setSbOpen(true)} aria-label="Open menu">☰</button>
          <span className="grow" />
          <span className="badge"><Pixels sm /> {me ? (me.serv ? <>SERV Reasoning<span className="hide-sm"> · {me.model}</span></> : "Deterministic planner") : "…"}</span>
          <button className="btn ghost icon" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} aria-label="Toggle dark mode" title="Toggle dark mode">{theme === "dark" ? "☀" : "☾"}</button>
        </div>

        <div className="thread" ref={threadRef}>
          <div className="thread-in">
            {items.length === 0 ? (
              <div className="empty">
                <Mark size={44} />
                <h1>Connect your mail or paste a suspicious link</h1>
                <p>Teger investigates links and emails with SERV Reasoning, then a deterministic engine gives the verdict. Paste a link or a whole email below, drop an <code>.eml</code> file, or try a sample.</p>
                <div className="start-row">
                  <button className="btn ember" onClick={() => setDrawer("inbox")}>{me?.inbox ? "✉ Scan my mail" : "✉ Connect mail"}</button>
                  {SAMPLE_LINKS.map((l) => (
                    <button key={l.url} className="linkchip" onClick={() => analyze({ body: l.url }, "link")} disabled={running} title={`Check ${l.url}`}>
                      <span className="lc-k">Try a link</span><code>{l.url.replace(/^https?:\/\//, "")}</code>
                    </button>
                  ))}
                </div>
                <div className="sub-k">Or simulate an attack</div>
                <div className="fx-grid">
                  {fixtures.map((f) => (
                    <button key={f.id} className={`fx ${f.expected === "no_threat_detected" ? "benign" : ""}`} onClick={() => analyze(f.message, "fixture")} disabled={running}>
                      <b>{f.label}</b><span>{f.kind}</span>
                    </button>
                  ))}
                </div>
                <div className="quick">
                  <button className="btn ghost sm" onClick={() => fileRef.current?.click()}>Upload .eml</button>
                </div>
              </div>
            ) : (
              items.map((it) => (
                <div key={it.key}>
                  <UserBubble item={it} />
                  <AgentReply item={it} onToast={notify} onLearn={(lists) => setMe((m) => (m ? { ...m, lists } : m))} canDraft={me?.inbox?.provider === "composio"} />
                </div>
              ))
            )}
          </div>
        </div>

        <div className="composer-wrap">
          <div className="composer">
            {showFields && (
              <div className="fields">
                <input className="input" placeholder="From: Name <sender@domain.com>" value={fields.sender} onChange={(e) => setFields({ ...fields, sender: e.target.value })} />
                <input className="input" placeholder="Reply-To (optional)" value={fields.reply_to} onChange={(e) => setFields({ ...fields, reply_to: e.target.value })} />
                <input className="input full" placeholder="Subject" value={fields.subject} onChange={(e) => setFields({ ...fields, subject: e.target.value })} />
                <textarea className="input full mono" rows={2} placeholder="Headers (Authentication-Results: spf=… dkim=… dmarc=…)" value={fields.headers} onChange={(e) => setFields({ ...fields, headers: e.target.value })} />
              </div>
            )}
            <textarea
              rows={Math.min(10, Math.max(1, text.split("\n").length))}
              placeholder="Connect your mail or paste a suspicious link…"
              value={text}
              onChange={(e) => setText(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) { e.preventDefault(); send(); } }}
              aria-label="Link or message to investigate"
            />
            <div className="bar">
              <button className={`tool ${showFields ? "on" : ""}`} onClick={() => setShowFields(!showFields)} title="Add sender, subject and headers">✉ Details</button>
              <button className="tool" onClick={() => fileRef.current?.click()} title="Upload an .eml file">⎙ .eml</button>
              <span className="grow" />
              <button className="btn ember sm connect" onClick={() => setDrawer("inbox")} title={me?.inbox ? "Scan messages from your connected mailbox" : "Connect Gmail or any IMAP mailbox"}>✉ {me?.inbox ? "Scan mail" : "Connect mail"}</button>
              <span className="hint" style={{ marginRight: 6 }}>⌘/Ctrl + Enter</span>
              <button className="send" onClick={send} disabled={running || (!text.trim() && !fields.subject.trim())} aria-label="Investigate">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#1a1714" strokeWidth="2.6" strokeLinecap="square"><path d="M12 19V5M5 12l7-7 7 7" /></svg>
              </button>
            </div>
            <input ref={fileRef} type="file" accept=".eml,message/rfc822,text/plain" hidden onChange={(e) => { const f = e.target.files?.[0]; if (f) onFile(f); e.target.value = ""; }} />
          </div>
          <div className="disclaim">Message content is treated as untrusted data. Links are checked server-side with SSRF protection and never opened on your device.</div>
        </div>
      </main>

      {drawer === "inbox" && me && <InboxDrawer me={me} onClose={() => setDrawer("")} onScan={scanInbox} refreshMe={refreshMe} />}
      {drawer === "settings" && me && <SettingsDrawer me={me} onClose={() => setDrawer("")} theme={theme} setTheme={setTheme} onLists={(lists) => setMe({ ...me, lists })} signOut={signOut} />}
      {toast && <div className="toast" role="status">{toast}</div>}
    </div>
  );
}
