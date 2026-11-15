# Changelog

## 2026-11-15: SERV Hackathon 02 submission

- **Paste a suspicious link**: URL-only input (bare domains too) runs the link tools end to end: safe resolution, look-alike and homoglyph checks, RDAP domain age and brand research. The workspace headline is now "Connect your mail or paste a suspicious link", with a Connect mail button and sample link chips.
- **Gmail via Composio**: one-click connect, inbox triage badges, scan, `TEGER_DO_NOT_TRUST` / `TEGER_CAUTION` labels, verification drafts, optional auto-scan webhook.
- **Explainer guardrail**: SERV explanations can't reassure, link out, cite unknown evidence or urge acting on a risky message.
- **Adversarial test suite**: a fully compromised planner and explainer can't move any verdict.
- **Evaluation harness** (`npm run eval`, [docs/EVAL.md](docs/EVAL.md)): deterministic, compromised-LLM and live SERV modes.
- **RDAP**: IANA bootstrap lookup for registry servers (domain age for more TLDs).
- **SSRF**: block hex-form IPv4-mapped IPv6.
- **CI**: lint, typecheck, tests, eval, build.
- Initial agent: SERV Reasoning tool-calling planner over 7 tools, deterministic policy, accounts, guest mode, history, learned allow/block lists, IMAP and Gmail OAuth.
