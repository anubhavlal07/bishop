/**
 * bishop.anubhavlal.dev -> bishop-console.netlify.app
 *
 * Netlify only serves a hostname that has been registered against the site, so
 * pointing DNS at it directly returns Netlify's own not-found page. This Worker
 * sits on the custom domain and rewrites the Host header to the one Netlify
 * recognises. Cloudflare terminates TLS, which also solves the certificate:
 * `bishop.anubhavlal.dev` is a third-level name and covered by the zone's
 * universal certificate.
 *
 * The console is a static export, so unlike the API proxy there is no streaming
 * to preserve and responses are safe to cache at the edge. Only the HTML is
 * held back — a stale index would pin visitors to an old JavaScript bundle
 * after a deploy, and the hashed assets under /_next/static are immutable by
 * construction so they can be cached hard.
 */

const ORIGIN = "bishop-console.netlify.app";

export default {
  async fetch(request) {
    const url = new URL(request.url);
    url.hostname = ORIGIN;
    url.protocol = "https:";
    url.port = "";

    const headers = new Headers(request.headers);
    headers.set("Host", ORIGIN);

    const upstream = await fetch(
      new Request(url.toString(), {
        method: request.method,
        headers,
        body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
        redirect: "manual",
      }),
    );

    const out = new Headers(upstream.headers);
    const immutable = url.pathname.startsWith("/_next/static/");
    out.set(
      "Cache-Control",
      immutable ? "public, max-age=31536000, immutable" : "public, max-age=0, must-revalidate",
    );

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: out,
    });
  },
};
