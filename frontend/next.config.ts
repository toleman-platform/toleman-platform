import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Lean production image for docker: standalone output bundles only the
  // files needed to run `node server.js` (traced dependencies), instead of
  // requiring the full node_modules tree in the runtime container.
  output: "standalone",
  // Disable the floating development indicator badge in dev mode
  devIndicators: false,
  // Allow tunneling tools (ngrok) in development
  allowedDevOrigins: ["*.ngrok-free.app", "*.ngrok.app", "*.ngrok.io", "localhost:3000"],
};

export default nextConfig;
