/** Server-side scan of one Gmail message (used by the Composio new-mail webhook). */
import { runAgent, AgentResult } from "../agent/agent";
import { getLists, memoryBackend } from "../agent/memory";
import { offlineNet, realNet } from "../agent/net";
import { servClient, servModel } from "../agent/serv";
import { saveAnalysis } from "../server/history";
import { getConn } from "./inbox";
import { fetchGmailViaComposio, labelGmailViaComposio } from "./composio";
import { getKV } from "../server/kv";

export async function autoScan(userId: string, messageId: string): Promise<{ verdict?: string; labeled?: string; skipped?: string }> {
  const c = await getConn(userId);
  if (c?.provider !== "composio" || !c.triggerId) return { skipped: "auto_scan_off" };
  if (!(await getKV().setNx(`autoscan:${userId}:${messageId}`, 1))) return { skipped: "duplicate" };
  await getKV().expire(`autoscan:${userId}:${messageId}`, 60 * 60 * 24 * 3);
  const message = await fetchGmailViaComposio(userId, c.connectedAccountId, messageId);
  let lists = { block: [] as string[], allow: [] as string[] };
  try { lists = await getLists(userId); } catch { /* empty */ }
  let final: AgentResult | undefined;
  await runAgent({
    message, lists, memoryBackend: memoryBackend(),
    toolEnv: { net: process.env.TEGER_OFFLINE === "1" ? offlineNet : realNet, env: process.env },
    client: servClient(), model: servModel(),
    onEvent: (e) => { if (e.type === "final") final = e.result; },
  });
  if (!final) return { skipped: "no_result" };
  let labeled: string | undefined;
  if (final.verdict === "malicious" || final.verdict === "suspicious") {
    labeled = final.verdict === "malicious" ? "TEGER_DO_NOT_TRUST" : "TEGER_CAUTION";
    try { await labelGmailViaComposio(userId, c.connectedAccountId, messageId, labeled as "TEGER_DO_NOT_TRUST"); } catch { labeled = undefined; }
  }
  await saveAnalysis(userId, "gmail-auto", message, final, { provider: "gmail", ref: messageId });
  return { verdict: final.verdict, labeled };
}
