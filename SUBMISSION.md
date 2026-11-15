# Teger Agent: OpenServ SERV Hackathon 02 submission

**Track:** Open Track
**Team:** DUKERS LTD (Emmanuel Effiom Duke)
**Repo:** https://github.com/dukemawex/teger-agent · **Live:** https://teger-agent.vercel.app

## Write-up (~200 words)

Teger Agent, built on SERV Reasoning, is an autonomous phishing and social-engineering investigator. You connect an inbox, upload an .eml or paste a suspicious message, and it runs the investigation a security analyst would. **SERV Reasoning is the agent's planner.** Through `chat/completions` tool calling, it decides which of seven tools to run (Teger's detectors, SPF/DKIM/DMARC, RDAP domain age, look-alike checks, SSRF-safe link resolution, brand research, isolated preview) and gives a reason for each call. It works within an 8-step budget and a token budget, then writes a plain-language explanation. The verdict itself comes from a deterministic policy, so a prompt-injected email can't talk the agent into calling it harmless. Message text is fenced as untrusted data, tools only touch domains that appear in the message, and every step is streamed and auditable.

Users sign in (or try it as a guest) and get a chat-style workspace: each analysis is a message with the verdict banner, evidence cards and the agent trace. Gmail (OAuth or IMAP app password) can be connected read-only, and Teger can apply a `TEGER_DO_NOT_TRUST` label on request; it never sends or deletes mail. Detectors cover AI-era attacks: look-alike letters ("EmaiI"), contradictory deadlines, borrowed brand contacts, reset storms with code relay, OAuth and device-code phishing, API-key requests and hidden prompt injection. Feedback goes into each user's allow/block lists, and the agent applies it on the next run.

## Revenue model
- **Free**: personal web checker with guest mode, and a planned Chrome extension (top-of-funnel adoption).
- **Team plan, per seat per month**: inbox and Slack protection that labels risky messages and drafts out-of-band verification, plus an admin audit log.
- **API**: usage-based verdict and explanation API for email-security vendors, MSPs and help desks.

## User readiness
- A deployed web app with accounts, guest mode, persistent per-user history and allow/block lists.
- Real inbox connection: IMAP (app password) works today; Gmail OAuth is built and turns on as soon as the OAuth client is configured.
- Eight simulated attacks plus a benign control, so judges can try it in seconds without an account.
- Public, auditable output (strict JSON plus a trace), ready to plug into mail and chat integrations.
