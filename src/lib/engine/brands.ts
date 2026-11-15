/**
 * Brand reference data (ported from teger_security_core/brands.py, extended for
 * domain/hosting brands frequently abused in renewal scams).
 */
export interface Brand {
  name: string;
  keywords: string[];
  domains: string[];
}

export const BRANDS: Brand[] = [
  { name: "PayPal", keywords: ["paypal"], domains: ["paypal.com", "paypal.me", "paypalobjects.com"] },
  {
    name: "Microsoft",
    keywords: ["microsoft", "office365", "outlook", "onedrive", "sharepoint"],
    domains: ["microsoft.com", "live.com", "office.com", "office365.com", "outlook.com", "microsoftonline.com", "sharepoint.com", "onedrive.com", "msn.com", "azure.com", "windows.net"],
  },
  { name: "Google", keywords: ["google", "gmail"], domains: ["google.com", "gmail.com", "youtube.com", "googleusercontent.com", "gstatic.com", "goo.gl", "g.co"] },
  { name: "Apple", keywords: ["apple", "icloud"], domains: ["apple.com", "icloud.com", "itunes.com", "me.com"] },
  { name: "Amazon", keywords: ["amazon"], domains: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.in", "amazon.ca", "amazon.com.au", "amazonaws.com"] },
  { name: "Netflix", keywords: ["netflix"], domains: ["netflix.com", "nflxext.com"] },
  { name: "Meta", keywords: ["facebook", "instagram", "whatsapp"], domains: ["facebook.com", "fb.com", "meta.com", "instagram.com", "whatsapp.com", "whatsapp.net", "messenger.com"] },
  { name: "LinkedIn", keywords: ["linkedin"], domains: ["linkedin.com", "lnkd.in"] },
  { name: "DocuSign", keywords: ["docusign"], domains: ["docusign.com", "docusign.net"] },
  { name: "Dropbox", keywords: ["dropbox"], domains: ["dropbox.com", "dropboxusercontent.com"] },
  { name: "DHL", keywords: ["dhl"], domains: ["dhl.com", "dhl.de"] },
  { name: "FedEx", keywords: ["fedex"], domains: ["fedex.com"] },
  { name: "UPS", keywords: ["ups"], domains: ["ups.com"] },
  { name: "USPS", keywords: ["usps"], domains: ["usps.com"] },
  { name: "Coinbase", keywords: ["coinbase"], domains: ["coinbase.com"] },
  { name: "Binance", keywords: ["binance"], domains: ["binance.com"] },
  { name: "Chase", keywords: ["chase"], domains: ["chase.com", "jpmorganchase.com"] },
  { name: "Wells Fargo", keywords: ["wellsfargo"], domains: ["wellsfargo.com"] },
  { name: "Bank of America", keywords: ["bankofamerica"], domains: ["bankofamerica.com", "bofa.com"] },
  { name: "Slack", keywords: ["slack"], domains: ["slack.com", "slack-edge.com"] },
  { name: "Namecheap", keywords: ["namecheap"], domains: ["namecheap.com", "privateemail.com"] },
  { name: "GoDaddy", keywords: ["godaddy"], domains: ["godaddy.com", "secureserver.net"] },
  { name: "GitHub", keywords: ["github"], domains: ["github.com", "githubusercontent.com"] },
];

export const OFFICIAL_DOMAINS = new Set(BRANDS.flatMap((b) => b.domains));

export const FREE_MAIL = new Set([
  "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", "proton.me", "protonmail.com", "aol.com", "gmx.com", "mail.com", "yandex.com",
]);

export function isOfficialDomain(reg?: string | null): boolean {
  return !!reg && OFFICIAL_DOMAINS.has(reg);
}

export function brandForDomain(reg?: string | null): Brand | undefined {
  if (!reg) return undefined;
  return BRANDS.find((b) => b.domains.includes(reg));
}

export function brandMentioned(brand: Brand, text: string): boolean {
  const lowered = text.toLowerCase();
  const names = new Set([brand.name.toLowerCase(), ...brand.keywords]);
  for (const n of names) {
    const esc = n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (new RegExp(`(?<![a-z0-9])${esc}(?![a-z0-9])`).test(lowered)) return true;
  }
  return false;
}
