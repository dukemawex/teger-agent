import OpenAI from "openai";
import { ChatClient, DEFAULT_MODEL, SERV_BASE_URL } from "./agent";

/** SERV Reasoning client: OpenAI SDK pointed at OpenServ's inference API. */
export function servClient(): ChatClient | undefined {
  const apiKey = process.env.SERV_API_KEY;
  if (!apiKey) return undefined;
  const client = new OpenAI({ baseURL: SERV_BASE_URL, apiKey, timeout: 45_000, maxRetries: 1 });
  return { create: (params) => client.chat.completions.create(params as never) as never };
}

export const servModel = () => process.env.SERV_MODEL || DEFAULT_MODEL;
