import { redirect } from "next/navigation";

/** Short link: /agent[?simulate=<fixture-id>] → the workspace at /app. */
export default async function AgentShortLink({ searchParams }: { searchParams: Promise<Record<string, string>> }) {
  const sp = await searchParams;
  redirect(sp.simulate ? `/app?simulate=${encodeURIComponent(sp.simulate)}` : "/app");
}
