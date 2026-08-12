import { Skeleton, SkeletonList } from "@/components/ui/skeleton";

export default function AuditLogLoading() {
  return (
    <div className="flex flex-col gap-6">
      <div>
        <Skeleton className="h-7 w-40" />
        <Skeleton className="mt-2 h-4 w-72" />
      </div>
      <SkeletonList count={6} />
    </div>
  );
}
