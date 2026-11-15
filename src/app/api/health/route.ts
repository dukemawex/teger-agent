import { memoryBackend } from "@/lib/agent/memory";
import { servModel } from "@/lib/agent/serv";
import { googleEnabled } from "@/lib/mail/google";
import { composioEnabled } from "@/lib/mail/composio";
export const dynamic = "force-dynamic";
export function GET() {
  return Response.json({
    ok: true,
    serv_reasoning: process.env.SERV_API_KEY ? "configured" : "not_configured (fallback planner)",
    model: servModel(),
    memory: memoryBackend(),
    auth: process.env.AUTH_SECRET ? "configured" : "dev-secret",
    composio_gmail: composioEnabled() ? "configured" : "not_configured",
    composio_webhook: process.env.COMPOSIO_WEBHOOK_SECRET ? "configured" : "not_configured",
    google_oauth: googleEnabled() ? "configured" : "not_configured",
    parallel: process.env.PARALLEL_API_KEY ? "configured" : "not_configured",
    instabox: process.env.INSTABOX_API_KEY ? "configured" : "not_configured",
  });
}
