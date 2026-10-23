// A template (unlike a layout) remounts on every navigation, which is what
// replays the entrance animation for each route without blocking input.
export default function DashboardTemplate({ children }: { children: React.ReactNode }) {
  return <div className="page-enter">{children}</div>;
}
