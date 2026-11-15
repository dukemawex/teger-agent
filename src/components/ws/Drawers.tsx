"use client";
import { useEffect, useState } from "react";
import { api } from "./client";

export interface Me {
  user: { id: string; email: string; name: string; provider: string } | null;
  guest: boolean;
  lists: { block: string[]; allow: string[] };
  inbox: { provider: string; account: string; host?: string; connectedAt: string; autoScan?: boolean } | null;
  google: boolean;
  composio: boolean;
  autoScanAvailable: boolean;
  serv: boolean;
  model: string;
  memory: string;
}

interface InboxMsg { ref: string; from: string; subject: string; date?: string; snippet?: string; triage?: { verdict: string; risk: number; top?: string } }
const TRIAGE: Record<string, string> = { malicious: "Likely scam", suspicious: "Suspicious", no_threat_detected: "Looks normal" };

const PRESETS: Record<string, { host: string; help: string; url: string }> = {
  gmail: { host: "imap.gmail.com", help: "Turn on 2-Step Verification, then create an app password.", url: "https://myaccount.google.com/apppasswords" },
  outlook: { host: "outlook.office365.com", help: "Create an app password under Advanced security options.", url: "https://account.live.com/proofs/AppPassword" },
  yahoo: { host: "imap.mail.yahoo.com", help: "Generate an app password in Account Security.", url: "https://login.yahoo.com/account/security" },
  icloud: { host: "imap.mail.me.com", help: "Create an app-specific password.", url: "https://appleid.apple.com/account/manage" },
  fastmail: { host: "imap.fastmail.com", help: "Create an app password (IMAP access).", url: "https://app.fastmail.com/settings/security/apps" },
  other: { host: "", help: "Use your provider's IMAP server and an app password.", url: "" },
};

function Drawer({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);
  return (
    <div className="overlay" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <aside className="drawer" role="dialog" aria-label={title}>
        <header><h3>{title}</h3><button className="btn ghost icon" onClick={onClose} aria-label="Close">✕</button></header>
        <div className="body">{children}</div>
      </aside>
    </div>
  );
}

export function InboxDrawer({ me, onClose, onScan, refreshMe }: { me: Me; onClose: () => void; onScan: (m: InboxMsg) => void; refreshMe: () => void }) {
  const [preset, setPreset] = useState("gmail");
  const [host, setHost] = useState(PRESETS.gmail.host);
  const [user, setUser] = useState(me.user?.email ?? "");
  const [pass, setPass] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [msgs, setMsgs] = useState<InboxMsg[] | null>(null);
  const [loadErr, setLoadErr] = useState("");
  const [suspiciousOnly, setSuspiciousOnly] = useState(false);
  const [total, setTotal] = useState(0);
  const [autoBusy, setAutoBusy] = useState(false);

  async function load(onlySuspicious = suspiciousOnly) {
    setMsgs(null); setLoadErr("");
    const { data } = await api<{ messages: InboxMsg[]; total?: number; error?: string }>(`/api/inbox${onlySuspicious ? "?filter=suspicious" : ""}`);
    setMsgs(data.messages ?? []);
    setTotal(data.total ?? 0);
    if (data.error) setLoadErr(data.error);
  }
  useEffect(() => { if (me.inbox) load(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [me.inbox?.account]);

  async function toggleAuto() {
    setAutoBusy(true); setLoadErr("");
    const { ok, data } = await api<{ error?: string }>("/api/inbox/composio/auto", { method: "POST", body: JSON.stringify({ enabled: !me.inbox?.autoScan }) });
    setAutoBusy(false);
    if (!ok) setLoadErr(data.error ?? "Couldn't change auto-scan.");
    refreshMe();
  }

  async function connect(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setErr("");
    const { ok, data } = await api<{ error?: string }>("/api/inbox/imap", { method: "POST", body: JSON.stringify({ host, port: 993, user, pass }) });
    setBusy(false);
    if (!ok) { setErr(data.error ?? "Couldn't connect."); return; }
    setPass("");
    refreshMe();
  }

  async function disconnect() {
    await api("/api/inbox", { method: "DELETE" });
    setMsgs(null);
    refreshMe();
  }

  if (!me.user) {
    return (
      <Drawer title="Connect your inbox" onClose={onClose}>
        <div className="option">
          <h4>Sign in to connect an inbox</h4>
          <p>Connected inboxes belong to an account, so your mailbox access, history and learned lists stay private to you.</p>
          <a className="btn" href="/signin?next=/app">Sign in or create an account</a>
        </div>
        <div className="option"><h4>Or bring a single email</h4><p>As a guest you can paste a message, or drop an <code>.eml</code> file (Gmail: ⋮ → Download message) into the composer. Full headers enable the SPF/DKIM/DMARC checks.</p></div>
      </Drawer>
    );
  }

  return (
    <Drawer title="Inbox" onClose={onClose}>
      {me.inbox ? (
        <>
          <div className="option">
            <h4><span className="status-dot on" /> Connected: {me.inbox.account}</h4>
            <p>{me.inbox.provider === "composio" ? "Gmail via Composio" : me.inbox.provider === "gmail" ? "Gmail via Google OAuth" : `IMAP · ${me.inbox.host}`} · reads mail, plus optional TEGER_* labels{me.inbox.provider === "composio" ? " and verification drafts" : ""}. Teger never sends, moves or deletes mail.</p>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <button className="btn ghost sm" onClick={() => load()}>Refresh</button>
              <button className={`btn sm ${suspiciousOnly ? "" : "ghost"}`} onClick={() => { const v = !suspiciousOnly; setSuspiciousOnly(v); load(v); }}>{suspiciousOnly ? "✓ Suspicious only" : "Suspicious only"}</button>
              <button className="btn ghost sm" onClick={disconnect}>Disconnect</button>
            </div>
            {me.inbox.provider === "composio" && (
              <div className="auto-row">
                <label className="switch"><input type="checkbox" checked={!!me.inbox.autoScan} disabled={autoBusy || !me.autoScanAvailable} onChange={toggleAuto} /><i /></label>
                <span><b>Auto-scan new mail</b><br /><em className="hint">{me.autoScanAvailable ? "New inbox messages are scanned and risky ones get a TEGER_* label. Results appear in History." : "Needs the Composio webhook on this deployment; manual scans work now."}</em></span>
              </div>
            )}
          </div>
          {loadErr && <div className="err">{loadErr}</div>}
          {!msgs && <p className="hint"><span className="spin" /> Loading recent messages…</p>}
          {msgs && msgs.length === 0 && !loadErr && <p className="hint">{suspiciousOnly ? `Quick triage found nothing suspicious in the last ${total} messages.` : "No messages in the inbox."}</p>}
          {msgs && msgs.length > 0 && <p className="hint">Last {total} messages · badges come from Teger&apos;s offline quick triage; Scan runs the full SERV agent.</p>}
          {msgs?.map((m) => (
            <div className="mail" key={m.ref}>
              <div>
                <div className="f">{m.from}{m.date ? ` · ${new Date(m.date).toLocaleString()}` : ""}</div>
                <div className="s">{m.triage && <span className={`tri t-${m.triage.verdict}`} title={m.triage.top ?? ""}>{TRIAGE[m.triage.verdict]}</span>}{m.subject}</div>
                {m.snippet && <div className="p">{m.snippet}</div>}
              </div>
              <button className="btn sm" onClick={() => onScan(m)}>Scan</button>
            </div>
          ))}
        </>
      ) : (
        <>
          <div className="option feature">
            <h4>Gmail <span className="pill-mini">via Composio</span></h4>
            <p>One click: approve access on Google&apos;s consent screen (hosted by Composio) and come straight back. Teger lists your recent mail, scans any message with the SERV agent, and can add TEGER_DO_NOT_TRUST / TEGER_CAUTION labels. Your Google tokens stay with Composio, never in Teger. Teger never sends or deletes mail.</p>
            {me.composio ? <a className="btn" href="/api/inbox/composio">Connect Gmail</a> : <p className="hint"><span className="status-dot" /> Composio isn&apos;t configured on this deployment yet (COMPOSIO_API_KEY). Use IMAP or an .eml file below.</p>}
          </div>
          {me.google && (
            <div className="option">
              <h4>Gmail (direct Google OAuth)</h4>
              <p>Alternative connection using this deployment&apos;s own Google OAuth client.</p>
              <a className="btn ghost" href="/api/auth/google?mode=gmail">Connect with Google</a>
            </div>
          )}
          <form className="option" onSubmit={connect}>
            <h4>Any mailbox via IMAP</h4>
            <p>Works with Gmail, Outlook.com, Yahoo, iCloud, Fastmail and more. Use an <b>app password</b>, not your normal password. It&apos;s stored encrypted (AES-256-GCM).</p>
            <label className="field"><span>Provider</span>
              <select className="input" value={preset} onChange={(e) => { setPreset(e.target.value); setHost(PRESETS[e.target.value].host); }}>
                {Object.keys(PRESETS).map((k) => <option key={k} value={k}>{k === "other" ? "Other (custom server)" : k[0].toUpperCase() + k.slice(1)}</option>)}
              </select>
            </label>
            {preset === "other" && <label className="field"><span>IMAP server</span><input className="input" value={host} onChange={(e) => setHost(e.target.value)} placeholder="imap.example.com" /></label>}
            <label className="field"><span>Email address</span><input className="input" type="email" required value={user} onChange={(e) => setUser(e.target.value)} /></label>
            <label className="field"><span>App password</span><input className="input" type="password" required value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="off" /></label>
            <p className="hint">{PRESETS[preset].help} {PRESETS[preset].url && <a href={PRESETS[preset].url} target="_blank" rel="noreferrer noopener">Open settings ↗</a>}</p>
            {err && <div className="err">{err}</div>}
            <button className="btn" disabled={busy}>{busy ? <span className="spin" /> : "Connect inbox"}</button>
          </form>
        </>
      )}
    </Drawer>
  );
}

export function SettingsDrawer({ me, onClose, theme, setTheme, onLists, signOut }: { me: Me; onClose: () => void; theme: string; setTheme: (t: string) => void; onLists: (l: Me["lists"]) => void; signOut: () => void }) {
  async function remove(domain: string) {
    const { data } = await api<{ lists: Me["lists"] }>("/api/feedback", { method: "DELETE", body: JSON.stringify({ domain }) });
    if (data.lists) onLists(data.lists);
  }
  return (
    <Drawer title="Settings" onClose={onClose}>
      <div className="option">
        <h4>Account</h4>
        {me.user ? (<><p>{me.user.name} · {me.user.email} · signed in with {me.user.provider}</p><button className="btn ghost sm" onClick={signOut}>Sign out</button></>) : (<><p>You&apos;re using guest mode. History and learned lists are kept for this browser for 7 days.</p><a className="btn sm" href="/signin?next=/app">Sign in</a></>)}
      </div>
      <div className="option">
        <h4>Appearance</h4>
        <div className="tabs" style={{ margin: 0 }}>
          {["light", "dark"].map((t) => <button key={t} className={theme === t ? "on" : ""} onClick={() => setTheme(t)}>{t === "light" ? "☀ Light" : "☾ Dark"}</button>)}
        </div>
      </div>
      <div className="option">
        <h4>What Teger has learned</h4>
        <p>Blocked senders are flagged malicious on sight. Trusted senders get lower risk, but critical signals still win.</p>
        <div className="field"><span>Blocked ({me.lists.block.length})</span><div className="lst">{me.lists.block.map((d) => <span key={d}>{d}<button onClick={() => remove(d)} aria-label={`Remove ${d}`}>✕</button></span>)}{!me.lists.block.length && <em className="hint">None yet</em>}</div></div>
        <div className="field"><span>Trusted ({me.lists.allow.length})</span><div className="lst">{me.lists.allow.map((d) => <span key={d}>{d}<button onClick={() => remove(d)} aria-label={`Remove ${d}`}>✕</button></span>)}{!me.lists.allow.length && <em className="hint">None yet</em>}</div></div>
      </div>
      <div className="option">
        <h4>Agent</h4>
        <p>Reasoning: {me.serv ? `SERV Reasoning (${me.model})` : "SERV key not configured on this deployment, so the deterministic planner is running"} · storage: {me.memory}</p>
      </div>
    </Drawer>
  );
}
