import { Skeleton, SkeletonList } from "@/components/ui/skeleton";

export default function FindingsLoading() {
  return (
    <div className="flex flex-col gap-6">
      <div>
        <Skeleton className="h-7 w-40" />
        <Skeleton className="mt-2 h-4 w-56" />
      </div>
      <Skeleton className="h-10 w-full" />
      <SkeletonList count={8} />
    </div>
  );
}
