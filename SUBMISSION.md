# Teger Agent: OpenServ SERV Hackathon 02 submission

**Track:** Open Track
**Team:** DUKERS LTD (Emmanuel Effiom Duke)
**Repo:** https://github.com/dukemawex/teger-agent · **Live:** https://teger-agent.vercel.app

## Write-up (~200 words)

Teger Agent, built on SERV Reasoning, is an autonomous phishing and social-engineering investigator. You connect your mail or paste a suspicious link (or a whole email), and it runs the investigation a security analyst would. **SERV Reasoning is the agent's planner.** Through `chat/completions` tool calling, it decides which of seven tools to run (Teger's detectors, SPF/DKIM/DMARC, RDAP domain age, look-alike checks, SSRF-safe link resolution, brand research, isolated preview) and gives a reason for each call. It works within an 8-step budget and a token budget, then writes a plain-language explanation. The verdict itself comes from a deterministic policy, so a prompt-injected email can't talk the agent into calling it harmless. Message text is fenced as untrusted data, tools only touch domains that appear in the message, and every step is streamed and auditable.

Users sign in (or try it as a guest) and get a chat-style workspace: each analysis is a message with the verdict banner, evidence cards and the agent trace. Gmail connects in one click through Composio (managed Google OAuth; tokens stay with Composio): Teger lists recent mail with an offline quick-triage badge, scans any message with the SERV agent, and on request applies a `TEGER_DO_NOT_TRUST` label or saves a verification draft. Composio sessions are pinned to read/label/draft tools only, so it never sends or deletes mail. IMAP and .eml remain as fallbacks. Detectors cover AI-era attacks: look-alike letters ("EmaiI"), contradictory deadlines, borrowed brand contacts, reset storms with code relay, OAuth and device-code phishing, API-key requests and hidden prompt injection. Feedback goes into each user's allow/block lists, and the agent applies it on the next run.

## Revenue model
- **Free**: personal web checker with guest mode, and a planned Chrome extension (top-of-funnel adoption).
- **Team plan, per seat per month**: inbox and Slack protection that labels risky messages and drafts out-of-band verification, plus an admin audit log.
- **API**: usage-based verdict and explanation API for email-security vendors, MSPs and help desks.

## User readiness
- A deployed web app with accounts, guest mode, persistent per-user history and allow/block lists.
- Real inbox connection: one-click Gmail via Composio, plus IMAP (app password) and .eml upload as fallbacks; optional auto-scan of new mail through a Composio trigger webhook.
- Seven simulated attacks, a benign control and two sample suspicious links, so judges can try it in seconds without an account.
- Public, auditable output (strict JSON plus a trace), ready to plug into mail and chat integrations.

## Evidence it works
- **Eval** ([docs/EVAL.md](docs/EVAL.md)): 10/10 correct verdicts with live SERV Reasoning (47 SERV calls, 84k tokens), 10/10 with no LLM, and 10/10 against a mocked *compromised* LLM that obeys a prompt injection.
- **CI** (lint, typecheck, 164 tests, eval, build) runs on every push: https://github.com/dukemawex/teger-agent/actions/workflows/ci.yml
- **Where SERV is used**, with exact file and line links: [README → How SERV Reasoning is used](README.md#how-serv-reasoning-is-used).
