import { Suspense } from "react";
import Workspace from "@/components/ws/Workspace";
import { FIXTURES } from "@/lib/fixtures";

export const metadata = { title: "Workspace · Teger Agent" };

export default function AppPage() {
  return <Suspense><Workspace fixtures={FIXTURES} /></Suspense>;
}
