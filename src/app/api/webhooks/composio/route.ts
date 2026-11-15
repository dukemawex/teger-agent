/**
 * Composio trigger webhook (GMAIL_NEW_GMAIL_MESSAGE). Signature is verified with COMPOSIO_WEBHOOK_SECRET
 * (HMAC-SHA256 over "webhook-id.webhook-timestamp.body", 5-minute tolerance) before anything runs.
 */
import { after } from "next/server";
import { composio, NEW_MESSAGE_TRIGGER } from "@/lib/mail/composio";
import { autoScan } from "@/lib/mail/autoscan";
export const runtime = "nodejs";
export const maxDuration = 60;
export const dynamic = "force-dynamic";
export async function POST(req: Request) {
  const secret = process.env.COMPOSIO_WEBHOOK_SECRET;
  if (!secret || !process.env.COMPOSIO_API_KEY) return Response.json({ error: "not_configured" }, { status: 503 });
  const body = await req.text();
  if (body.length > 200_000) return Response.json({ error: "too_large" }, { status: 413 });
  let ev: Awaited<ReturnType<Awaited<ReturnType<typeof composio>>["verifyWebhook"]>>;
  try { ev = await (await composio()).verifyWebhook(body, req.headers, secret); } catch { return Response.json({ error: "invalid_signature" }, { status: 401 }); }
  if (ev.triggerSlug !== NEW_MESSAGE_TRIGGER || !ev.userId) return Response.json({ ok: true, ignored: true });
  const p = ev.payload as Record<string, unknown>;
  const messageId = String(p.message_id ?? p.messageId ?? p.id ?? "");
  if (!/^[A-Za-z0-9]{1,40}$/.test(messageId)) return Response.json({ ok: true, ignored: "no_message_id" });
  after(async () => { try { await autoScan(ev.userId, messageId); } catch (e) { console.error("autoscan failed:", String((e as Error).message).slice(0, 200)); } });
  return Response.json({ ok: true });
}
