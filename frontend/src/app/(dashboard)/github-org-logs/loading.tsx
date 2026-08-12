import { Skeleton, SkeletonList } from "@/components/ui/skeleton";

export default function GithubOrgLogsLoading() {
  return (
    <div className="flex flex-col gap-6">
      <div>
        <Skeleton className="h-7 w-56" />
        <Skeleton className="mt-2 h-4 w-full max-w-xl" />
      </div>
      <SkeletonList count={6} />
    </div>
  );
}
