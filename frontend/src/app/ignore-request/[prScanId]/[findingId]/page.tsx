import { IgnoreRequestClient } from "./ignore-request-client";

export default async function IgnoreRequestPage({
  params,
}: {
  params: Promise<{ prScanId: string; findingId: string }>;
}) {
  const { prScanId, findingId } = await params;
  return <IgnoreRequestClient prScanId={Number(prScanId)} findingId={Number(findingId)} />;
}
