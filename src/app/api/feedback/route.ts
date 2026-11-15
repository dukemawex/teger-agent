import { addToList, getLists, removeFromLists, sanitizeDomain } from "@/lib/agent/memory";
import { isOfficialDomain } from "@/lib/engine/brands";
import { registrableDomain } from "@/lib/engine/urls";
import { resolveIdentity } from "@/lib/server/identity";
import { fail, guard, json, readJson } from "@/lib/server/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const id = await resolveIdentity(req);
  return json(id ? await getLists(id.id) : { block: [], allow: [] });
}

export async function POST(req: Request) {
  const g = guard(req, "fb", 40);
  if (g) return g;
  const body = await readJson(req, 2000);
  const id = await resolveIdentity(req);
  if (!id) return fail("no_identity", 401);
  const d = sanitizeDomain(body?.domain);
  const label = body?.label === "scam" ? "block" : body?.label === "legit" ? "allow" : undefined;
  if (!d || !label) return fail("bad_request");
  const domain = registrableDomain(d) ?? d;
  // One click must never block a major brand's official domain; that would hide real mail.
  if (label === "block" && isOfficialDomain(domain)) return json({ ok: false, reason: "official_domain", lists: await getLists(id.id) });
  return json({ ok: true, domain, list: label, lists: await addToList(id.id, label, domain) });
}

export async function DELETE(req: Request) {
  const g = guard(req, "fb", 40);
  if (g) return g;
  const body = await readJson(req, 2000);
  const id = await resolveIdentity(req);
  const d = sanitizeDomain(body?.domain);
  if (!id || !d) return fail("bad_request");
  return json({ ok: true, lists: await removeFromLists(id.id, d) });
}
