/** End-to-end IMAP test against a local hoodiecrow server (run with IMAP_IT=1; see README). */
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { createRequire } from "node:module";
import { listImap, fetchImapRaw, labelImap, testImap } from "../src/lib/mail/imap";
import { parseRawEmail } from "../src/lib/mail/parse";
import { runAgent } from "../src/lib/agent/agent";
import { offlineNet } from "../src/lib/agent/net";

const RUN = process.env.IMAP_IT === "1";
const cfg = { host: "127.0.0.1", port: 1143, user: "demo", pass: "demopass" };
const phish = ["From: Email Services <noreply@internationalgroupcolleferro.it>", "To: user@example-recipient.com", "Subject: Renew Your Private EmaiI Subscription", "Authentication-Results: mx.example-recipient.com; spf=softfail; dkim=none; dmarc=fail", "Date: Thu, 12 Nov 2026 09:00:00 +0000", "", "Your Private Email subscription expired on 05/11/2026. You are in a 30-Day Grace Period. Renew before 13/11/2026 or your mailbox will be permanently deleted. Contact help@namecheap.com. https://privateemail-renewal-portal.top/namecheap/renew"].join("\r\n");
const benign = ["From: GitHub <noreply@github.com>", "To: user@example-recipient.com", "Subject: CI run completed", "Date: Thu, 12 Nov 2026 10:00:00 +0000", "", "The workflow CI on main completed successfully."].join("\r\n");

describe.runIf(RUN)("IMAP connector (local server)", () => {
  let server: { listen: (p: number, cb: () => void) => void; close: (cb?: () => void) => void };
  beforeAll(async () => {
    process.env.TEGER_IMAP_ALLOW_PRIVATE = "1";
    const req = createRequire(import.meta.url);
    const hoodiecrow = req(process.env.HOODIECROW_PATH ?? "hoodiecrow-imap");
    server = hoodiecrow({ plugins: ["ID", "IDLE", "UNSELECT", "ENABLE", "X-GM-EXT-1"], users: { demo: { password: "demopass" } }, storage: { INBOX: { messages: [{ raw: benign, flags: [] }, { raw: phish, flags: [] }] } } });
    await new Promise<void>((r) => server.listen(1143, r));
  });
  afterAll(() => new Promise<void>((r) => server.close(() => r())));

  it("connects, lists, fetches, scans and labels", async () => {
    expect((await testImap(cfg)).messages).toBe(2);
    const list = await listImap(cfg);
    expect(list[0].subject).toBe("Renew Your Private EmaiI Subscription");
    const msg = await parseRawEmail(await fetchImapRaw(cfg, list[0].ref));
    const r = await runAgent({ message: msg, lists: { block: [], allow: [] }, toolEnv: { net: offlineNet, env: {} } });
    expect(r.verdict).toBe("malicious");
    expect(["gmail-label", "imap-keyword"]).toContain(await labelImap(cfg, list[0].ref, "TEGER_DO_NOT_TRUST"));
  }, 30000);
});
