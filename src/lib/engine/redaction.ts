/** Produce a short, redacted excerpt around a match so evidence can be quoted safely. */
export function redact(s: string): string {
  return s
    .replace(/\b[A-Z]{2}\d{2}[A-Z0-9 ]{10,30}\b/g, (m) => m.slice(0, 4) + "…[IBAN redacted]")
    .replace(/\b\d{6}\b/g, "[code]")
    .replace(/\b(?:\d[ -]?){13,19}\b/g, "[card redacted]")
    .replace(/\b(sk|pk|ghp|gho|xox[bap])[-_][A-Za-z0-9_-]{8,}\b/g, "[secret redacted]");
}

export function excerpt(text: string, start: number, end: number, pad = 40): string {
  const s = Math.max(0, start - pad);
  const e = Math.min(text.length, end + pad);
  const raw = (s > 0 ? "…" : "") + text.slice(s, e).replace(/\s+/g, " ").trim() + (e < text.length ? "…" : "");
  return redact(raw).slice(0, 220);
}
