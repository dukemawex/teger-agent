# Architecture

Teger Agent has three layers with a hard boundary between them. **SERV Reasoning** chooses what to investigate and how to explain it. **Tools** gather evidence. A **deterministic policy** turns that evidence into the verdict. The model never sets the verdict.

```
src/
  lib/
    engine/        deterministic, pure, no network, no model
      engine.ts        runs the five local detector families over a message
      advanced.ts      AI-era detectors: homoglyph text, contradictory deadlines, borrowed brand
                       contacts, code relay / reset storms, OAuth consent, device code,
                       secret requests, QR / parcel lures, hidden prompt injection
      brand.ts         look-alike / typosquat / brand-on-untrusted-domain host checks
      language.ts      credential + social-engineering rules (BEC, gift cards, urgency…)
      senderAuth.ts    SPF / DKIM / DMARC results, From vs Reply-To
      urls.ts, urlHeuristics.ts   URL parsing, registrable domains, URL red flags
      linkCheck.ts     link-only input ("paste a suspicious link") + imitated-brand hint
      policy.ts        decide(): evidence + coverage → verdict, score, banner (POLICY_VERSION)
    agent/
      serv.ts          SERV Reasoning client (OpenAI SDK → inference-api.openserv.ai/v1)
      agent.ts         Observe → Plan → Investigate → Decide → Explain loop, budgets,
                       fallback planner, explainer guardrail (sanitizeExplanation)
      tools.ts         7 function tools + their JSON schemas; tools write evidence directly
      net.ts           SSRF-safe fetch (private ranges, redirect re-check, size/time caps)
      memory.ts        per-identity allow / block lists ("Teger learned: …")
    mail/            Gmail via Composio (allow-listed tools), IMAP, Google OAuth, .eml parsing,
                     offline inbox triage, optional auto-scan webhook
    server/          accounts (scrypt), HMAC sessions, AES-GCM secrets, Upstash KV, history
  app/api/         Next.js route handlers (agent stream, feedback, history, inbox, auth, health)
  components/ws/   chat-style workspace UI (verdict banner, evidence cards, live agent trace)
tests/           unit + integration + adversarial tests (SERV mocked, no network)
eval/            fixture evaluation harness → docs/EVAL.md
```

## Request flow (`POST /api/agent`)

1. **Guard**: same-origin check, per-IP and per-identity rate limits, 40 KB cap, field clipping.
2. **Observe** (deterministic): link-only detection, URL / domain extraction, and the domain scope (only domains in the message can be inspected). Learned lists are loaded.
3. **Plan + Investigate** (SERV): `chat.completions` with `tools`, `tool_choice: "auto"` and `parallel_tool_calls: true`. Each tool call carries a `why`, and results go back as `tool` messages. The budgets are 8 tool steps and 60k tokens.
4. **Decide** (deterministic): `decide` merges all evidence, including the local detectors even if the model skipped them, plus the learned lists, and runs `policy.decide`. If the model never calls `decide`, the agent calls it.
5. **Explain** (SERV): JSON-mode summary, reasons and steps. Output goes through `sanitizeExplanation`, and Teger templates fill anything that gets dropped.
6. **Stream**: NDJSON events (`start`, `step`, `final`, `saved`) feed the live trace in the UI. The result is saved to history.

## Failure modes

| Failure | Behaviour |
|---|---|
| No `SERV_API_KEY` | Deterministic fallback planner; UI badge says "Deterministic planner" |
| SERV error or timeout mid-run | Evidence gathered so far is kept, the fallback planner finishes, and `planner_note` explains why |
| Explainer error | Teger templates are used, noted in the trace |
| A detector throws | Its report is `error`, coverage becomes `partial`, and a clean result becomes `unknown`, never "no warning signs" |
| RDAP / link fetch unavailable | Reported in the tool output; never turned into evidence either way |
| KV store down | Empty lists; history save is best-effort |
