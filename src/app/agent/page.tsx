import { redirect } from "next/navigation";
export default async function Legacy({ searchParams }: { searchParams: Promise<Record<string, string>> }) {
  const sp = await searchParams;
  redirect(sp.simulate ? `/app?simulate=${encodeURIComponent(sp.simulate)}` : "/app");
}
