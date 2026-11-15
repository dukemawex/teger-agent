/**
 * Hackathon detectors (new in Teger Agent): text homoglyphs, inconsistent deadlines,
 * cited brand contact vs unrelated sender, reset storms / code relay, OAuth consent
 * and device-code lures, secret-material requests, hidden prompt injection, QR lures.
 */
import { BRANDS, brandForDomain, FREE_MAIL } from "./brands";
import { excerpt } from "./redaction";
import { applyRules, Rule } from "./language";
import { registrableDomain, senderDomain } from "./urls";
import { FindingCollector } from "./types";

/** Words that scammers disguise by swapping 'l' for capital 'I' (or digits for letters). */
const LURE_WORDS = [
  "email", "mail", "billing", "apple", "paypal", "login", "help", "wallet", "support", "renewal", "cancel", "final", "official",
  "helpdesk", "microsoft", "google", "netflix", "linkedin", "dropbox", "invoice", "account", "verify", "password", "secure", "online", "global",
  "delivery", "parcel", "bank", "payment", "subscription", "service", "unlock", "alert", "outlook", "icloud", "coinbase", "binance", "amazon",
];
const DIGIT_MAP: Record<string, string> = { "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s" };
const CYR = /[\u0400-\u04ff\u0370-\u03ff]/;

export function textHomoglyphs(text: string, c: FindingCollector) {
  for (const m of text.matchAll(/[\p{L}\p{N}$]{3,}/gu)) {
    const w = m[0];
    // Capital I inside or at the end of an otherwise lower-case word, e.g. "EmaiI".
    if (/[a-z]I(?:[a-z]|$)/.test(w)) {
      const fixed = w.replace(/(?<=[a-z])I/g, "l").toLowerCase();
      if (LURE_WORDS.some((lw) => fixed === lw || fixed.startsWith(lw) || fixed.endsWith(lw))) {
        c.add({ category: "text_homoglyph", severity: "high", tactic: "link_manipulation",
          description: `The word "${w}" uses a capital 'I' in place of a lower-case 'l' to slip past filters (reads as "${fixed}").`,
          indicator: excerpt(text, m.index!, m.index! + w.length) });
        return;
      }
    }
    // Mixed Latin + Cyrillic/Greek letters inside one word.
    if (CYR.test(w) && /[a-z]/i.test(w)) {
      c.add({ category: "text_homoglyph", severity: "high", tactic: "link_manipulation",
        description: `The word "${w}" mixes Latin and Cyrillic/Greek look-alike letters.`, indicator: excerpt(text, m.index!, m.index! + w.length) });
      return;
    }
    // Digits standing in for letters, e.g. "PayPa1", "Micr0soft".
    if (/[a-z]/i.test(w) && /[0-9$]/.test(w) && !/^\d/.test(w)) {
      const fixed = [...w.toLowerCase()].map((ch) => DIGIT_MAP[ch] ?? ch).join("");
      if (LURE_WORDS.includes(fixed) || BRANDS.some((b) => b.keywords.includes(fixed))) {
        c.add({ category: "text_homoglyph", severity: "high", tactic: "link_manipulation",
          description: `The word "${w}" swaps digits for letters (reads as "${fixed}").`, indicator: excerpt(text, m.index!, m.index! + w.length) });
        return;
      }
    }
  }
}

function parseDates(text: string): { date: Date; index: number; raw: string }[] {
  const out: { date: Date; index: number; raw: string }[] = [];
  for (const m of text.matchAll(/\b(\d{1,2})[/.-](\d{1,2})[/.-](\d{4})\b/g)) {
    const d = Number(m[1]), mo = Number(m[2]), y = Number(m[3]);
    if (mo >= 1 && mo <= 12 && d >= 1 && d <= 31) out.push({ date: new Date(Date.UTC(y, mo - 1, d)), index: m.index!, raw: m[0] });
  }
  return out;
}

/** Contradictory deadlines, e.g. "30-Day Grace Period" but "renew before" a date 8 days after expiry. */
export function inconsistentDeadlines(text: string, c: FindingCollector) {
  const grace = text.match(/\b(\d{1,3})[- ]?days?\s+grace(?:\s+period)?\b/i) ?? text.match(/\bgrace period of (\d{1,3}) days?\b/i);
  const dates = parseDates(text);
  if (grace && dates.length >= 2) {
    const g = Number(grace[1]);
    const sorted = [...dates].sort((a, b) => a.date.getTime() - b.date.getTime());
    const span = Math.round((sorted[sorted.length - 1].date.getTime() - sorted[0].date.getTime()) / 86400000);
    if (span > 0 && Math.abs(span - g) >= 3) {
      c.add({ category: "inconsistent_deadlines", severity: "high", tactic: "artificial_urgency",
        description: `The message promises a ${g}-day grace period, but its own dates (${sorted[0].raw} → ${sorted[sorted.length - 1].raw}) leave only ${span} days. Real providers don't contradict themselves; scammers bolt urgency onto templates.`,
        indicator: excerpt(text, grace.index!, grace.index! + grace[0].length) });
      return;
    }
  }
  const nums = [...text.matchAll(/\b(\d{1,3})[- ]?(?:days?|hours?)\b/gi)].map((m) => m[0].toLowerCase().replace(/[- ]/, " "));
  const distinct = new Set(nums.map((n) => n.replace(/s$/, "")));
  if (distinct.size >= 3 && /\b(deadline|expire|before|within|suspend)\w*/i.test(text)) {
    c.add({ category: "inconsistent_deadlines", severity: "medium", tactic: "artificial_urgency",
      description: `The message gives several conflicting time limits (${[...distinct].slice(0, 3).join(", ")}).`, indicator: [...distinct].join(", ") });
  }
}

/** Body cites an official brand contact (e.g. help@namecheap.com) while the sender domain is unrelated. */
export function citedBrandContact(sender: string, text: string, c: FindingCollector) {
  const sd = senderDomain(sender);
  const sreg = sd ? registrableDomain(sd) : undefined;
  if (!sreg) return;
  for (const m of text.matchAll(/[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/g)) {
    const reg = registrableDomain(m[1].toLowerCase());
    const brand = brandForDomain(reg);
    if (brand && !brand.domains.includes(sreg)) {
      c.add({ category: "cited_brand_contact_mismatch", severity: "high", tactic: "trust_transfer",
        description: `The message cites ${brand.name}'s official contact (${m[0]}) to borrow its trust, but it was sent from ${sd}, a domain ${brand.name} does not use.`,
        indicator: `${m[0]} vs sender @${sd}` });
      return;
    }
  }
  // Sender domain is unrelated to the brand named in the subject/body text.
  if (!FREE_MAIL.has(sreg)) {
    for (const b of BRANDS) {
      const named = new RegExp(`\\b(your|from|by|with)\\s+${b.name}\\b`, "i").test(text);
      if (named && !b.domains.includes(sreg)) {
        c.add({ category: "brand_claim_unrelated_sender", severity: "medium", tactic: "authority_spoofing",
          description: `The message speaks for ${b.name}, but the sender domain ${sd} is not one of ${b.name}'s.`, indicator: `@${sd}` });
        return;
      }
    }
  }
}

const ADV_RULES: Rule[] = [
  { category: "code_relay_request", tactic: "credential_harvesting", severity: "critical",
    description: "Asks you to read back or forward a verification/reset code you just received. That code is the key to your account; whoever asks for it is taking it over.",
    pattern: /\b(read|send|forward|tell|give|share|reply with|provide|confirm)\b[^.\n]{0,60}\b(code|otp|pin)\b[^.\n]{0,60}\b(just )?(sent|received|got|texted|arrived)\b|\b(code|otp)\b[^.\n]{0,40}\b(we|i)\s+(just\s+)?sent\b[^.\n]{0,60}\b(read|send|share|reply|tell)\b/i },
  { category: "reset_or_code_storm", tactic: "credential_harvesting", severity: "high",
    description: "Several password-reset / verification-code messages you did not request. A burst like this usually means someone is trying to take over the account.",
    pattern: /(?:(?:password reset|reset your password|verification code|security code|sign-?in code|login code|one-time code)[\s\S]{0,600}){3,}/i },
  { category: "oauth_consent_lure", tactic: "credential_harvesting", severity: "high",
    description: "Pushes you to authorize an app or grant mailbox/drive permissions. Consent phishing steals access without ever needing your password.",
    pattern: /\b(authori[sz]e|grant|allow|approve|accept)\b[^.\n]{0,60}\b(app|application|integration|permissions?|access)\b[^\n]{0,120}\b(mail|mailbox|inbox|drive|files|contacts|calendar|offline access|read\/?write)\b|\b(mail\.read|files\.readwrite|offline_access)\b/i },
  { category: "device_code_phish", tactic: "credential_harvesting", severity: "critical",
    description: "Asks you to enter a code on a device-login page. Device-code phishing hands your signed-in session to the attacker.",
    pattern: /\b(microsoft\.com\/devicelogin|aka\.ms\/devicelogin|google\.com\/device|github\.com\/login\/device)\b|\bdevice (?:login|code)\b[^.\n]{0,60}\benter\b/i },
  { category: "secret_material_request", tactic: "credential_harvesting", severity: "critical",
    description: "Asks for API keys, client secrets, tokens, SSH keys or .env/config files. No legitimate audit asks you to paste secrets into email or chat.",
    pattern: /\b(send|share|paste|provide|upload|attach|email|reply with|forward)\b[^.\n]{0,80}\b(api[- ]?keys?|client secrets?|secret keys?|access tokens?|auth tokens?|ssh (?:private )?keys?|\.env\b|env(?:ironment)? file|aws (?:access )?keys?|credentials? file|service account (?:key|json))/i },
  { category: "qr_code_lure", tactic: "link_manipulation", severity: "medium",
    description: "Asks you to scan a QR code, which hides the real link from your email filters and moves you to a less-protected phone.",
    pattern: /\bscan (?:the|this|our)?\s*(?:attached |below )?qr[- ]?code\b|\bqr[- ]?code\b[^.\n]{0,60}\b(scan|pay|confirm|reschedule|verify)\b/i },
  { category: "parcel_fee_lure", tactic: "payment_redirection", severity: "medium",
    description: "Claims a parcel is held until a small fee is paid, a common delivery-scam pattern.",
    pattern: /\b(parcel|package|shipment|delivery)\b[^\n]{0,120}\b(on hold|held|failed|could not be delivered|pending)\b[^\n]{0,160}\b(fee|pay|payment|charge)\b/i },
];

const ZERO_WIDTH = /[\u200b-\u200f\u2060-\u2064\ufeff]/g;
const HIDDEN_HTML = /<[^>]+style\s*=\s*["'][^"']*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*(#fff(?:fff)?|white)|opacity\s*:\s*0)[^"']*["'][^>]*>([\s\S]{0,400}?)<\//i;
const INJECTION = /\b(ignore (?:all |any )?(?:previous|prior|above|earlier) (?:instructions|rules)|disregard (?:the|your|all) (?:system|previous|prior)? ?(?:prompt|instructions)|you are (?:now )?an? (?:ai|assistant|language model)|system prompt|(?:ai|assistant|copilot|agent)s?(?: reading this)?[,:]? (?:please )?(?:forward|approve|pay|mark|classify|summari[sz]e this as|reply)|(?:mark|classify|label|treat) this (?:email|message) as (?:safe|legitimate|benign|trusted|not spam))/i;

export function promptInjection(rawText: string, c: FindingCollector) {
  const zw = rawText.match(ZERO_WIDTH);
  const hidden = HIDDEN_HTML.exec(rawText);
  const visibleText = rawText.replace(ZERO_WIDTH, "");
  const inj = INJECTION.exec(visibleText);
  if (inj && (hidden || (zw && zw.length >= 3))) {
    c.add({ category: "hidden_prompt_injection", severity: "critical", tactic: "context_injection",
      description: "Hidden text (invisible HTML or zero-width characters) carries instructions aimed at AI assistants that read your mail. Teger treated it as data and ignored it.",
      indicator: excerpt(visibleText, inj.index, inj.index + inj[0].length) });
  } else if (inj) {
    c.add({ category: "ai_instruction_injection", severity: "high", tactic: "context_injection",
      description: "Contains instructions aimed at an AI assistant reading the message.", indicator: excerpt(visibleText, inj.index, inj.index + inj[0].length) });
  } else if (hidden && hidden[3].replace(/<[^>]+>/g, "").trim().length > 20) {
    c.add({ category: "hidden_text", severity: "medium", tactic: "context_injection",
      description: "The message contains text styled to be invisible to you.", indicator: excerpt(hidden[3], 0, Math.min(80, hidden[3].length)) });
  } else if (zw && zw.length >= 5) {
    c.add({ category: "zero_width_obfuscation", severity: "medium", tactic: "context_injection",
      description: `The message contains ${zw.length} invisible zero-width characters, used to break up words and evade filters.`, indicator: `${zw.length} zero-width chars` });
  }
}

export function advancedDetector(sender: string, text: string, rawText: string, c: FindingCollector) {
  textHomoglyphs(text, c);
  inconsistentDeadlines(text, c);
  citedBrandContact(sender, text, c);
  applyRules(ADV_RULES, text, c);
  promptInjection(rawText, c);
}
