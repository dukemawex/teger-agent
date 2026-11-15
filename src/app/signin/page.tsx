import { Suspense } from "react";
import { Logo, Pixels, PixelShield } from "@/components/Logo";
import SignInForm from "@/components/SignInForm";
import { googleEnabled } from "@/lib/mail/google";

export const metadata = { title: "Sign in · Teger Agent" };
export const dynamic = "force-dynamic";

export default function SignIn() {
  return (
    <main className="auth">
      <section className="auth-art">
        <Logo />
        <div style={{ maxWidth: 360, margin: "32px 0" }}><PixelShield /></div>
        <div>
          <h2>Your inbox, investigated by an agent that shows its work.</h2>
          <p style={{ opacity: .7, marginTop: 14 }}><Pixels sm /> &nbsp;Built on SERV Reasoning</p>
        </div>
        <hr className="ember-rule" style={{ position: "absolute", left: 0, right: 0, bottom: 0 }} />
      </section>
      <section className="auth-main">
        <Suspense><SignInForm google={googleEnabled()} /></Suspense>
      </section>
    </main>
  );
}
