/**
 * A static export.
 *
 * Every page in this console is a client component that talks to Bishop's API
 * directly, so there is nothing for a Node server to do at request time. Static
 * output means the console is files on a CDN: it deploys to Cloudflare Pages,
 * Netlify, S3 or a USB stick without change, costs nothing to run, and cannot
 * fall over independently of the API.
 *
 * `trailingSlash` matters for static hosting. Without it a request for
 * `/triage` looks for a file called `triage` rather than `triage/index.html`,
 * and most static hosts return 404.
 */
const nextConfig = {
  reactStrictMode: true,
  output: "export",
  trailingSlash: true,
  images: { unoptimized: true },
};

export default nextConfig;
