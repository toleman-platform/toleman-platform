import { Skeleton, SkeletonList } from "@/components/ui/skeleton";

export default function TargetDetailLoading() {
  return (
    <div className="flex flex-col gap-8">
      <div>
        <Skeleton className="h-7 w-64" />
        <Skeleton className="mt-2 h-4 w-96" />
      </div>
      <Skeleton className="h-24 w-full rounded-xl" />
      <Skeleton className="h-32 w-full rounded-xl" />
      <SkeletonList count={4} />
    </div>
  );
}
