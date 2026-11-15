"use client";
import { useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Logo } from "./Logo";

export default function SignInForm({ google }: { google: boolean }) {
  const router = useRouter();
  const params = useSearchParams();
  const [mode, setMode] = useState<"in" | "up">(params.get("mode") === "up" ? "up" : "in");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const next = params.get("next")?.startsWith("/") ? params.get("next")! : "/app";

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setErr("");
    try {
      const r = await fetch(mode === "in" ? "/api/auth/login" : "/api/auth/signup", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email, password, name }) });
      const j = await r.json();
      if (!r.ok) { setErr(j.error === "busy" ? "Too many attempts. Wait a minute and try again." : j.error || "Something went wrong."); return; }
      router.push(next);
      router.refresh();
    } catch {
      setErr("Network error. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-card">
      <div className="mob-logo"><Logo /></div>
      <h1>{mode === "in" ? "Welcome back" : "Create your account"}</h1>
      <p className="hint">Accounts keep your analysis history, your learned allow/block lists and your connected inbox.</p>
      <div className="tabs" role="tablist">
        <button className={mode === "in" ? "on" : ""} onClick={() => setMode("in")} type="button">Sign in</button>
        <button className={mode === "up" ? "on" : ""} onClick={() => setMode("up")} type="button">Sign up</button>
      </div>
      {google && (
        <>
          <a className="btn ghost" style={{ width: "100%" }} href="/api/auth/google?mode=signin">
            <svg width="16" height="16" viewBox="0 0 48 48" aria-hidden><path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3C33.7 32.7 29.2 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.4-.4-3.5z"/><path fill="#FF3D00" d="m6.3 14.7 6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 16.3 4 9.7 8.3 6.3 14.7z"/><path fill="#4CAF50" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.2 35.1 26.7 36 24 36c-5.2 0-9.6-3.3-11.3-7.9l-6.5 5C9.5 39.6 16.2 44 24 44z"/><path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.2-2.2 4.2-4.1 5.6l6.2 5.2C37 39.2 44 34 44 24c0-1.3-.1-2.4-.4-3.5z"/></svg>
            Continue with Google
          </a>
          <div className="or">or</div>
        </>
      )}
      <form onSubmit={submit}>
        {mode === "up" && <label className="field"><span>Name</span><input className="input" value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" /></label>}
        <label className="field"><span>Email</span><input className="input" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" /></label>
        <label className="field"><span>Password</span><input className="input" type="password" required minLength={8} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete={mode === "in" ? "current-password" : "new-password"} /></label>
        {err && <div className="err">{err}</div>}
        <button className="btn" style={{ width: "100%" }} disabled={busy}>{busy ? <span className="spin" /> : mode === "in" ? "Sign in" : "Create account"}</button>
      </form>
      <div className="or">or</div>
      <a className="btn ghost" style={{ width: "100%" }} href="/app">Continue as guest</a>
      <p className="hint" style={{ marginTop: 14 }}>Guest analyses are kept on this device for 7 days. Passwords are hashed with scrypt, and sessions use signed, HTTP-only cookies.</p>
    </div>
  );
}
