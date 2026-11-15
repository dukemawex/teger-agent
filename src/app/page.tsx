import { Logo, Mark, Pixels, PixelShield } from "@/components/Logo";

const STEPS = [
  ["01", "Observe", "Your message is fenced as untrusted data. Teger pulls out every link, domain and contact in scope."],
  ["02", "Plan", "SERV Reasoning decides which checks matter for this message and records why."],
  ["03", "Investigate", "Real tool calls: sender auth, domain age, look-alike letters, safe link resolution, brand research."],
  ["04", "Decide", "A deterministic policy turns the evidence into a verdict the model cannot change."],
  ["05", "Explain", "You get a plain-language banner, evidence quotes and what to do instead."],
];

export default function Home() {
  return (
    <main className="lp">
      <header className="lp-nav">
        <Logo />
        <nav>
          <a className="nl" href="#how">How it works</a>
          <a className="nl" href="#detects">What it catches</a>
          <a className="nl" href="https://github.com/dukemawex/teger-agent">GitHub</a>
          <a className="btn ghost sm" href="/signin">Sign in</a>
          <a className="btn sm" href="/app">Try the demo</a>
        </nav>
      </header>

      <section className="hero">
        <div>
          <span className="badge"><Pixels sm /> Built on SERV Reasoning · SERV Hackathon 02</span>
          <h1>Stop phishing <span className="em">before</span> anyone clicks.</h1>
          <p className="lead">Teger Agent is an autonomous investigator for suspicious links and email. Connect your mail, paste a suspicious link or a whole message. SERV Reasoning plans the checks, real tools gather evidence, and a deterministic engine gives a verdict that a prompt-injected email can&apos;t talk its way out of.</p>
          <form className="hero-check" action="/app" method="get">
            <label htmlFor="hero-link">Connect your mail or paste a suspicious link</label>
            <div className="row">
              <input id="hero-link" name="link" className="input" placeholder="paypa1-secure-login.top/verify" autoComplete="off" spellCheck={false} maxLength={2000} required />
              <button className="btn ember" type="submit">Check link →</button>
            </div>
          </form>
          <div className="cta">
            <a className="btn" href="/app?connect=1">✉ Connect mail</a>
            <a className="btn ghost" href="/app?simulate=fake-renewal">Simulate an attack</a>
          </div>
        </div>
        <PixelShield />
      </section>

      <hr className="ember-rule" />

      <section className="sect" id="how">
        <span className="kicker"><Pixels sm /> How it works</span>
        <h2>An analyst&apos;s workflow, run by an agent, with every step on the record.</h2>
        <div className="steps">
          {STEPS.map(([n, t, d]) => (
            <div className="step" key={n}><div className="n">{n}</div><h3>{t}</h3><p>{d}</p></div>
          ))}
        </div>
      </section>

      <section className="sect" id="detects">
        <span className="kicker"><Pixels sm /> Why it holds up</span>
        <h2>Reasoning where it helps. Rules where it counts.</h2>
        <div className="grid3">
          <div className="tile"><Mark /><h3>SERV plans, rules decide</h3><p>SERV Reasoning drives tool calling and explanations through OpenServ&apos;s inference API. The verdict comes from deterministic policy, so the model can&apos;t be argued into calling a scam harmless.</p></div>
          <div className="tile"><Mark /><h3>Connected to your inbox</h3><p>Sign in, connect Gmail or any IMAP mailbox with an app password, and scan real messages. Teger can label threats <code>TEGER_DO_NOT_TRUST</code>. It never sends, moves or deletes mail.</p></div>
          <div className="tile"><Mark /><h3>Learns from you</h3><p>Confirm a scam or mark a sender as legitimate. Your allow and block lists are saved to your account and used on every later run.</p></div>
        </div>
        <div style={{ marginTop: 22 }} className="chips">
          {["Fake renewals & invoices", "Look-alike letters (EmaiI)", "Contradictory deadlines", "BEC & IBAN changes", "CEO gift cards", "Reset storms & code relay", "OAuth consent phishing", "Device-code phishing", "QR parcel scams", "API-key requests", "Hidden prompt injection", "SPF / DKIM / DMARC"].map((c) => <span className="chip" key={c}>{c}</span>)}
        </div>
      </section>

      <section className="cta-band">
        <div className="in">
          <h2>Connect your mail or paste a suspicious link. See the agent think.</h2>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <a className="btn ember" href="/app">Try as guest</a>
            <a className="btn ghost" href="/signin">Sign in</a>
          </div>
          <hr className="ember-rule" />
        </div>
      </section>

      <footer className="lp-foot">
        <span>© 2026 DUKERS LTD · Emmanuel Effiom Duke</span>
        <span>Teger Agent: built on SERV Reasoning for the OpenServ SERV Hackathon 02 (Open Track) · <a href="https://github.com/dukemawex/teger-agent">Source (MIT)</a></span>
      </footer>
    </main>
  );
}
