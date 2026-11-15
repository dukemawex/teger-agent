import type { AgentResult } from "../agent/agent";
import type { MessageInput } from "../engine/engine";
import { getKV } from "./kv";
import { randomId } from "./crypto";

export interface HistoryItem {
  id: string;
  createdAt: string;
  source: string;
  subject: string;
  sender: string;
  verdict: string;
  risk: number;
}

export interface HistoryRecord extends HistoryItem {
  message: MessageInput;
  result: AgentResult;
  inbox?: { provider: "imap" | "gmail"; ref: string };
}

const MAX = 50;
const GUEST_TTL = 60 * 60 * 24 * 7;

export async function saveAnalysis(identity: string, source: string, message: MessageInput, result: AgentResult, inbox?: HistoryRecord["inbox"]): Promise<HistoryItem> {
  const kv = getKV();
  const item: HistoryItem = {
    id: "a_" + randomId(9),
    createdAt: new Date().toISOString(),
    source,
    subject: (message.subject || message.body || "(no subject)").slice(0, 120),
    sender: (message.sender || "").slice(0, 160),
    verdict: result.verdict,
    risk: result.risk_score,
  };
  const trimmed: AgentResult = { ...result, screenshots: result.screenshots.map((s) => ({ ...s, image: undefined })) };
  const rec: HistoryRecord = { ...item, message: { ...message, body: message.body?.slice(0, 8000) }, result: trimmed, inbox };
  const ttl = identity.startsWith("g_") ? GUEST_TTL : 60 * 60 * 24 * 180;
  await kv.set(`analysis:${identity}:${item.id}`, rec, ttl);
  await kv.lpush(`history:${identity}`, item, MAX);
  if (identity.startsWith("g_")) await kv.expire(`history:${identity}`, GUEST_TTL);
  return item;
}

export const listHistory = (identity: string) => getKV().lrange<HistoryItem>(`history:${identity}`, 0, MAX - 1);
export const getAnalysis = (identity: string, id: string) => (/^a_[A-Za-z0-9_-]{6,20}$/.test(id) ? getKV().get<HistoryRecord>(`analysis:${identity}:${id}`) : Promise.resolve(null));
