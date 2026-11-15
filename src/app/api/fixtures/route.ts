import { FIXTURES } from "@/lib/fixtures";
export function GET() {
  return Response.json(FIXTURES);
}
