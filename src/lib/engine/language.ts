/** Deterministic language detectors (ported from teger_security_core/detectors/language.py). */
import { excerpt } from "./redaction";
import { Finding, FindingCollector, Severity } from "./types";

export interface Rule {
  category: string;
  tactic: string;
  severity: Severity;
  description: string;
  pattern: RegExp;
}

const rx = (p: string) => new RegExp(p, "i");

export const CREDENTIAL_RULES: Rule[] = [
  { category: "secret_phrase_request", tactic: "credential_harvesting", severity: "critical",
    description: "Asks for a wallet seed / recovery phrase or private key, which no legitimate service requests.",
    pattern: rx(String.raw`\b(seed|recovery|secret|mnemonic)\s+(phrase|words)\b|\bprivate\s+key\b`) },
  { category: "credential_request", tactic: "credential_harvesting", severity: "high",
    description: "Asks the recipient to send or confirm a password, PIN or one-time code.",
    pattern: rx(String.raw`\b(send|share|provide|confirm|reply with|give|tell|enter|read)\b[^.\n]{0,40}\b(password|passcode|pin|otp|one[- ]time (?:code|password)|verification code|security code|2fa code|mfa code|login credentials?)\b`) },
  { category: "account_verification_lure", tactic: "credential_harvesting", severity: "medium",
    description: "Pushes the recipient to log in or 'verify' an account through a link.",
    pattern: rx(String.raw`\b(verify|validate|confirm|re-?activate|unlock|update)\s+(your\s+)?(account|identity|login|credentials|mailbox|billing (?:info|information|details))\b|\b(log ?in|sign ?in)\s+(here|below|now|to (?:verify|confirm|restore|avoid))\b`) },
  { category: "mfa_fatigue", tactic: "credential_harvesting", severity: "high",
    description: "Asks the recipient to approve a sign-in prompt they did not start.",
    pattern: rx(String.raw`\b(approve|accept|tap yes on)\b[^.\n]{0,30}\b(sign-?in|login|push|mfa|authenticator)\b`) },
];

export const SOCIAL_RULES: Rule[] = [
  { category: "urgent_language", tactic: "artificial_urgency", severity: "medium",
    description: "Creates time pressure to rush a decision.",
    pattern: rx(String.raw`\b(urgent(ly)?|immediately|right now|asap|within \d+ (?:minutes?|hours?)|final (?:notice|warning)|act now|expires? (?:today|tonight|in \d+)|last chance|before end of day)\b`) },
  { category: "consequence_threat", tactic: "consequence_threat", severity: "medium",
    description: "Threatens account loss, penalties or legal action to coerce compliance.",
    pattern: rx(String.raw`\b(account|mailbox|access|e-?mail|service|subscription|domain)s?\s+(will be|has been|is|are)\s+(permanently\s+)?(suspended|locked|closed|terminated|deleted|disabled|deactivated|lost)|\b(legal action|arrest|penalt(?:y|ies)|lawsuit|prosecut\w*)\b|\b(lose|losing) (?:access|all (?:your )?(?:emails?|data|files))\b`) },
  { category: "gift_card_request", tactic: "payment_redirection", severity: "high",
    description: "Requests gift cards or their codes, a hallmark of executive-impersonation scams.",
    pattern: rx(String.raw`\bgift\s?cards?\b|\b(itunes|google play|steam|amazon)\s+cards?\b`) },
  { category: "payment_change_request", tactic: "payment_redirection", severity: "high",
    description: "Announces changed bank details or asks to pay a new account.",
    pattern: rx(String.raw`\b(new|updated|changed?|different)\s+(bank|banking|account|wire|payment|remittance)\s+(details?|information|info|instructions|account)\b|\bbank(?:ing)? details have (?:changed|been updated)\b|\b(new|updated) iban\b`) },
  { category: "financial_request", tactic: "payment_redirection", severity: "medium",
    description: "Requests a payment, transfer or crypto transaction.",
    pattern: rx(String.raw`\b(wire transfer|bank transfer|send (?:money|funds|payment)|outstanding invoice|pay(?:ment)? (?:now|immediately|today)|bitcoin|btc|usdt|crypto(?:currency)? wallet|redelivery fee|customs fee|small fee)\b`) },
  { category: "authority_claim", tactic: "authority_spoofing", severity: "low",
    description: "Invokes an executive, IT, bank or government authority.",
    pattern: rx(String.raw`\b(ceo|cfo|chief executive|managing director|finance director|it (?:helpdesk|support|department)|system administrator|security team|tax (?:office|authority)|irs|hmrc|police|federal|government)\b`) },
  { category: "secrecy_or_bypass", tactic: "pretexting", severity: "medium",
    description: "Asks for secrecy or to bypass normal verification and approval.",
    pattern: rx(String.raw`\b(keep (?:this|it) (?:between us|confidential|quiet)|do not (?:tell|call|discuss)|don'?t (?:tell|call)|bypass|skip (?:the )?(?:approval|process|verification)|i'?m in a meeting|can'?t talk)\b`) },
  { category: "reward_bait", tactic: "reciprocity_bait", severity: "medium",
    description: "Offers an unexpected prize, refund or windfall.",
    pattern: rx(String.raw`\b(you(?:'ve| have)? won|winner|lottery|prize|inheritance|unclaimed (?:funds|refund)|refund of|cash reward|claim your (?:reward|prize|refund))\b`) },
  { category: "emotional_pressure", tactic: "emotional_anchoring", severity: "low",
    description: "Uses fear, sympathy or embarrassment to short-circuit judgment.",
    pattern: rx(String.raw`\b(i'?m (?:stuck|stranded)|emergency|please help me|i'?m begging|embarrassing|compromising (?:video|photos?)|we have (?:your|recorded))\b`) },
  { category: "attachment_lure", tactic: "attachment_lure", severity: "medium",
    description: "Pressures the recipient to open an attachment or enable document content.",
    pattern: rx(String.raw`\b(enable (?:macros|content|editing)|open the attached|see (?:the )?attached (?:invoice|document|file|payment)|download the (?:attached|invoice|document))\b`) },
];

export function applyRules(rules: Rule[], text: string, c: FindingCollector) {
  for (const r of rules) {
    const m = r.pattern.exec(text);
    if (m) {
      c.add({ category: r.category, severity: r.severity, description: r.description, tactic: r.tactic,
        indicator: excerpt(text, m.index, m.index + m[0].length) } satisfies Finding);
    }
  }
}
