# Security policy

Teger Agent analyses hostile content (phishing email and links) by design, so its security model is part of the product. This page lists what it defends against, how, and how to report a problem.

## Reporting a vulnerability

Please open a [private security advisory](https://github.com/dukemawex/teger-agent/security/advisories/new) on GitHub. Don't open a public issue for anything exploitable. Expect an acknowledgement within 72 hours.

## Threat model

| Threat | Defence | Where | Tested in |
|---|---|---|---|
| Prompt-injected email talks the LLM into "safe" | The verdict is a pure function of evidence (`decide`); the LLM never sets it. Explainer output passes `sanitizeExplanation` (no reassurance, no links, only real evidence ids, no calls to act on a risky message). | `src/lib/engine/policy.ts`, `src/lib/agent/agent.ts` | `tests/injection.test.ts` (fully compromised planner + explainer on every fixture) |
| Injection steers tools at internal targets (SSRF) | Tools only accept domains/links that appear in the submitted message; network layer blocks private, loopback, link-local, CGNAT, metadata, multicast, reserved and IPv4-mapped IPv6 ranges, re-checks every redirect hop, allows ports 80/443 only, refuses credentials in URLs, caps 6 s / 200 KB | `src/lib/agent/tools.ts`, `src/lib/agent/net.ts` | `tests/net.test.ts`, `tests/tools.test.ts`, `tests/agent.test.ts` |
| Model invents evidence | Tools write evidence directly into run state; the model only sees summaries. `analyze_message` always reads the original message, never model-supplied text | `src/lib/agent/tools.ts` | `tests/injection.test.ts` |
| Runaway agent loop / cost | 8 tool-step budget, 60k token budget, 45 s SERV timeout, then deterministic completion | `src/lib/agent/agent.ts` | `tests/agent.test.ts` |
| SERV outage or bad key | Deterministic fallback planner runs the same tools; result is labelled `planner: "fallback"` with a visible note | `src/lib/agent/agent.ts` | `tests/agent.test.ts` |
| Mail account abuse | Teger never sends, moves or deletes mail. Composio sessions are pinned to an allow-list of read/label/draft tools; IMAP passwords and OAuth tokens are AES-256-GCM encrypted at rest | `src/lib/mail/*`, `src/lib/server/crypto.ts` | `tests/composio.test.ts`, `tests/server.test.ts` |
| Session forgery / CSRF | scrypt password hashes, HMAC-signed HttpOnly cookies, same-origin check on every state-changing route | `src/lib/server/auth.ts`, `src/lib/server/http.ts` | `tests/server.test.ts` |
| Abuse / DoS | 40 KB request cap, per-IP and per-identity rate limits | `src/lib/server/http.ts`, `src/lib/ratelimit.ts` | – |

## Known limitations

- **DNS rebinding window.** The SSRF guard resolves a hostname and then `fetch` resolves it again. A hostile DNS server could answer differently the second time. Pinning the resolved IP needs a custom agent and isn't done yet. Exposure is limited because the server runs on Vercel serverless with no internal services next to it.
- **Rate limits are per instance** (in-memory), so they reset on cold start and aren't shared across serverless instances.
- **Heuristic detectors** can miss novel lures and can over-flag unusual legitimate mail. The verdict is labelled "No warning signs found", never "safe".
- **Brand list** is a curated reference list, not an exhaustive registry. Web brand research (Parallel) is optional.

## Secrets

No secret is shipped to the browser, logged or committed. `/api/health` reports only whether an integration is configured, never its value. `.env*` files are git-ignored except `.env.example`, which holds no values.
