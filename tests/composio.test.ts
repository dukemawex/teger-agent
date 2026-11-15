import { beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryKV, setKVForTests, getKV } from "../src/lib/server/kv";
import { ALLOWED_TOOLS, ComposioApi, labelGmailViaComposio, setComposioForTests, toInboxList, toMessageInput, listGmailViaComposio } from "../src/lib/mail/composio";
import { triage } from "../src/lib/mail/triage";
import { describe as describeConn, getConn, saveComposio } from "../src/lib/mail/inbox";

const ME = { id: "u_test123", email: "me@example.com", name: "Me", provider: "password", createdAt: "" };
vi.mock("../src/lib/server/auth", async (orig) => ({ ...(await orig<object>()), currentUser: async () => ME }));

const b64u = (s: string) => Buffer.from(s).toString("base64url");
const FULL = {
  data: {
    messageId: "19b11732c1b578fd", sender: "Namecheap <billing@internationalgroupcolleferro.it>", subject: "Renew Your Private EmaiI Subscription",
    payload: {
      mimeType: "multipart/alternative",
      headers: [
        { name: "From", value: "Namecheap <billing@internationalgroupcolleferro.it>" },
        { name: "Reply-To", value: "renewals@paypa1-billing.top" },
        { name: "Subject", value: "Renew Your Private EmaiI Subscription" },
        { name: "Authentication-Results", value: "mx.google.com; dmarc=fail" },
        { name: "X-Irrelevant", value: "drop me" },
      ],
      parts: [
        { mimeType: "text/plain", body: { data: b64u("Renew now at http://namecheap-renewal.top/login within 24 hours or lose your mailbox.") } },
        { mimeType: "text/html", body: { data: b64u("<p>Renew now at <a href='http://namecheap-renewal.top/login'>login</a> within 24 hours or lose your mailbox. Enter your password to verify.</p>") } },
      ],
    },
  },
};

function mockApi(over: Partial<ComposioApi> = {}) {
  const calls: { tool: string; args: Record<string, unknown> }[] = [];
  const labels: { id: string; name: string }[] = [{ id: "INBOX", name: "INBOX" }];
  const api: ComposioApi = {
    createLink: async (userId, cb) => ({ redirectUrl: `https://connect.composio.dev/link/ln_test?u=${userId}&cb=${encodeURIComponent(cb)}`, connectedAccountId: "ca_new1" }),
    listAccounts: async (userId) => (userId === ME.id ? [{ id: "ca_new1", status: "ACTIVE", toolkit: "gmail" }] : []),
    deleteAccount: async () => undefined,
    createTrigger: async () => "ti_1",
    deleteTrigger: async () => undefined,
    verifyWebhook: async () => ({ userId: ME.id, triggerSlug: "GMAIL_NEW_GMAIL_MESSAGE", payload: { message_id: "19b11732c1b578fd" } }),
    execute: async (_u, _ca, tool, args) => {
      expect(ALLOWED_TOOLS).toContain(tool);
      calls.push({ tool, args });
      if (tool === "GMAIL_FETCH_EMAILS") return { messages: [
        { messageId: "a1", sender: "GitHub <noreply@github.com>", subject: "Your weekly digest", messageTimestamp: "2026-11-15T10:00:00Z", preview: { body: "Here is what happened in your repositories this week." } },
        { messageId: "b2", sender: "Microsoft Support <help@m1crosoft-security.top>", subject: "Urgent: verify your account", messageTimestamp: "2026-11-15T11:00:00Z", messageText: "Your account will be suspended in 24 hours. Verify your password now at http://m1crosoft-security.top/login and read the code back to us." },
        { messageId: "../bad", sender: "x", subject: "y" },
      ] };
      if (tool === "GMAIL_FETCH_MESSAGE_BY_MESSAGE_ID") return FULL;
      if (tool === "GMAIL_LIST_LABELS") return { labels };
      if (tool === "GMAIL_CREATE_LABEL") { const l = { id: "Label_9", name: String(args.label_name) }; labels.push(l); return l; }
      if (tool === "GMAIL_GET_PROFILE") return { emailAddress: "me@gmail.com" };
      return {};
    },
    ...over,
  };
  return { api, calls };
}

beforeEach(() => { const kv = new MemoryKV(); kv.m.clear(); setKVForTests(kv); setComposioForTests(null); });

describe("Composio Gmail normalisation", () => {
  it("maps FETCH_EMAILS to inbox rows, drops unsafe ids, and triages deterministically", async () => {
    const { api } = mockApi(); setComposioForTests(api);
    const rows = await listGmailViaComposio(ME.id, "ca_new1");
    expect(rows.map((r) => r.ref)).toEqual(["a1", "b2"]);
    const t = rows.map((r) => triage({ sender: r.from, subject: r.subject, body: r.snippet }));
    expect(t[0].verdict).toBe("no_threat_detected");
    expect(t[1].verdict).not.toBe("no_threat_detected");
  });
  it("turns a full Gmail payload into MessageInput with auth headers and the HTML body", async () => {
    const m = await toMessageInput(FULL);
    expect(m.sender).toContain("internationalgroupcolleferro.it");
    expect(m.reply_to).toBe("renewals@paypa1-billing.top");
    expect(m.headers).toContain("dmarc=fail");
    expect(m.headers).not.toContain("X-Irrelevant");
    expect(m.body).toContain("<a href='http://namecheap-renewal.top/login'>");
  });
  it("handles raw (RFC 822) responses too", async () => {
    const raw = "From: A <a@example.com>\r\nSubject: Hi\r\nDate: Sun, 15 Nov 2026 10:00:00 +0000\r\n\r\nHello there";
    const m = await toMessageInput({ data: { raw: Buffer.from(raw).toString("base64url") } });
    expect(m.subject).toBe("Hi");
    expect(m.body).toContain("Hello there");
  });
  it("tolerates empty data", () => { expect(toInboxList({})).toEqual([]); });
});

describe("Composio protective actions", () => {
  it("creates the TEGER label once when missing, then adds it; never calls send/delete tools", async () => {
    const { api, calls } = mockApi(); setComposioForTests(api);
    await labelGmailViaComposio(ME.id, "ca_new1", "b2", "TEGER_DO_NOT_TRUST");
    await labelGmailViaComposio(ME.id, "ca_new1", "a1", "TEGER_DO_NOT_TRUST");
    expect(calls.filter((c) => c.tool === "GMAIL_CREATE_LABEL")).toHaveLength(1);
    const adds = calls.filter((c) => c.tool === "GMAIL_ADD_LABEL_TO_EMAIL");
    expect(adds.map((a) => a.args.add_label_ids)).toEqual([["Label_9"], ["Label_9"]]);
    expect(calls.some((c) => /SEND|DELETE|TRASH|FORWARD/.test(c.tool))).toBe(false);
    expect(ALLOWED_TOOLS.some((t) => /SEND|DELETE|TRASH|FORWARD|FILTER/.test(t))).toBe(false);
  });
});

describe("Composio connect flow (routes, mocked Composio)", () => {
  it("reports not-configured when there is no key", async () => {
    delete process.env.COMPOSIO_API_KEY;
    const { GET } = await import("../src/app/api/inbox/composio/route");
    const r = await GET(new Request("http://localhost:3000/api/inbox/composio"));
    expect(r.headers.get("location")).toContain("notice=composio_not_configured");
  });
  it("redirects to the Composio link, then the callback verifies ownership and saves the connection", async () => {
    const { api } = mockApi(); setComposioForTests(api);
    const start = await import("../src/app/api/inbox/composio/route");
    const r = await start.GET(new Request("http://localhost:3000/api/inbox/composio"));
    const loc = r.headers.get("location")!;
    expect(loc).toMatch(/^https:\/\/connect\.composio\.dev\/link\//);
    const cb = new URL(decodeURIComponent(new URL(loc).searchParams.get("cb")!));
    expect(cb.pathname).toBe("/api/inbox/composio/callback");
    const state = cb.searchParams.get("state")!;
    const done = await import("../src/app/api/inbox/composio/callback/route");
    // Wrong state is rejected
    const bad = await done.GET(new Request(`http://localhost:3000/api/inbox/composio/callback?state=nope&status=success&connected_account_id=ca_new1`));
    expect(bad.headers.get("location")).toContain("composio_failed");
    // Re-start (the bad attempt consumed nothing) and complete properly
    const pending = await getKV().get<{ state: string }>(`czpending:${ME.id}`);
    expect(pending?.state).toBe(state);
    const ok = await done.GET(new Request(`http://localhost:3000/api/inbox/composio/callback?state=${state}&status=success&connected_account_id=ca_new1`));
    expect(ok.headers.get("location")).toContain("notice=gmail_connected");
    const conn = await getConn(ME.id);
    expect(conn).toMatchObject({ provider: "composio", connectedAccountId: "ca_new1", email: "me@gmail.com" });
    expect(describeConn(conn)).toMatchObject({ provider: "composio", account: "me@gmail.com", autoScan: false });
  });
  it("rejects a connected account that belongs to someone else", async () => {
    const { api } = mockApi({ listAccounts: async () => [{ id: "ca_other", status: "ACTIVE", toolkit: "gmail" }] }); setComposioForTests(api);
    await getKV().set(`czpending:${ME.id}`, { state: "s1", connectedAccountId: null }, 900);
    const done = await import("../src/app/api/inbox/composio/callback/route");
    const r = await done.GET(new Request(`http://localhost:3000/api/inbox/composio/callback?state=s1&status=success&connected_account_id=ca_new1`));
    expect(r.headers.get("location")).toContain("composio_failed");
    expect(await getConn(ME.id)).toBeNull();
  });
  it("lists, fetches and labels through the generic inbox routes", async () => {
    const { api, calls } = mockApi(); setComposioForTests(api);
    await saveComposio(ME.id, "ca_new1", "me@gmail.com");
    const inbox = await import("../src/app/api/inbox/route");
    const all = await (await inbox.GET(new Request("http://localhost:3000/api/inbox"))).json();
    expect(all.messages).toHaveLength(2);
    const sus = await (await inbox.GET(new Request("http://localhost:3000/api/inbox?filter=suspicious"))).json();
    expect(sus.messages.map((m: { ref: string }) => m.ref)).toEqual(["b2"]);
    const msg = await import("../src/app/api/inbox/message/route");
    const got = await (await msg.GET(new Request("http://localhost:3000/api/inbox/message?ref=19b11732c1b578fd"))).json();
    expect(got.provider).toBe("gmail");
    expect(got.message.headers).toContain("dmarc=fail");
    const label = await import("../src/app/api/inbox/label/route");
    const lr = await label.POST(new Request("http://localhost:3000/api/inbox/label", { method: "POST", headers: { origin: "http://localhost:3000", host: "localhost:3000", "content-type": "application/json" }, body: JSON.stringify({ ref: "19b11732c1b578fd", label: "TEGER_CAUTION" }) }));
    expect(lr.status).toBe(200);
    expect(calls.at(-1)).toMatchObject({ tool: "GMAIL_ADD_LABEL_TO_EMAIL", args: { message_id: "19b11732c1b578fd" } });
  });
  it("webhook rejects missing config and bad signatures", async () => {
    const { api } = mockApi({ verifyWebhook: async () => { throw new Error("bad sig"); } }); setComposioForTests(api);
    const wh = await import("../src/app/api/webhooks/composio/route");
    delete process.env.COMPOSIO_WEBHOOK_SECRET;
    expect((await wh.POST(new Request("http://x/api/webhooks/composio", { method: "POST", body: "{}" }))).status).toBe(503);
    process.env.COMPOSIO_WEBHOOK_SECRET = "whsec_test"; process.env.COMPOSIO_API_KEY = "test";
    expect((await wh.POST(new Request("http://x/api/webhooks/composio", { method: "POST", body: "{}" }))).status).toBe(401);
    delete process.env.COMPOSIO_WEBHOOK_SECRET; delete process.env.COMPOSIO_API_KEY;
  });
});
