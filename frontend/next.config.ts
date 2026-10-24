import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Lean production image for docker: standalone output bundles only the
  // files needed to run `node server.js` (traced dependencies), instead of
  // requiring the full node_modules tree in the runtime container.
  output: "standalone",
  // Disable the floating development indicator badge in dev mode
  devIndicators: false,
  // Security headers absent from every response (a live-site check against
  // /login found HSTS present, from Cloudflare, but nothing from this app
  // itself). Applied at the framework level so Caddy/Cloudflare in front
  // don't have to be trusted to add them, and so every route gets them,
  // not just the ones someone remembers.
  //
  // Deliberately no Content-Security-Policy here: getting one right for a
  // Next.js app that may use inline styles/scripts in ways not audited as
  // part of this change risks breaking real pages in production, which is
  // a worse outcome than shipping without a CSP for now. Add one in a
  // follow-up once the app's actual script/style sources are enumerated.
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
        ],
      },
    ];
  },
};

export default nextConfig;
