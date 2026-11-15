import { currentUser, User } from "./auth";
import { sanitizeGuestId } from "../agent/memory";

export interface Identity {
  id: string;
  user: User | null;
  guest: boolean;
}

/** Signed-in user, else the browser's guest id (header x-teger-guest). */
export async function resolveIdentity(req: Request): Promise<Identity | null> {
  const user = await currentUser();
  if (user) return { id: user.id, user, guest: false };
  const g = sanitizeGuestId(req.headers.get("x-teger-guest"));
  return g ? { id: g, user: null, guest: true } : null;
}
