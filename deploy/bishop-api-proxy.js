/**
 * api.bishop.anubhavlal.dev -> bishop-api.onrender.com
 *
 * Render will only serve a hostname that has been registered against the
 * service, so pointing DNS at it directly returns 404. This Worker sits on the
 * custom domain, rewrites the Host header to the origin Render does recognise,
 * and passes everything else through untouched. Cloudflare terminates TLS, so
 * the certificate is handled without Render being involved at all.
 *
 * The one thing that would quietly break here is Bishop's SSE stream. The
 * console watches a run over `text/event-stream`, and a proxy that buffers the
 * response body turns a live topology view into a page that shows nothing for
 * twenty seconds and then everything at once. `response.body` is a
 * ReadableStream and is handed back untouched, which is what keeps it flowing;
 * the explicit no-cache on that path stops anything downstream deciding to
 * collect it first.
 */

const ORIGIN = "bishop-api.onrender.com";

export default {
  async fetch(request) {
    const url = new URL(request.url);
    url.hostname = ORIGIN;
    url.protocol = "https:";
    url.port = "";

    const headers = new Headers(request.headers);
    headers.set("Host", ORIGIN);
    // So the API can still see the real client for its rate limiter, rather
    // than counting every visitor as one Cloudflare edge address.
    const clientIp = request.headers.get("CF-Connecting-IP");
    if (clientIp) headers.set("X-Forwarded-For", clientIp);

    const isStream = url.pathname.endsWith("/events");

    const upstream = await fetch(
      new Request(url.toString(), {
        method: request.method,
        headers,
        body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
        redirect: "manual",
      }),
      // Never cache. Triage results are per-run and an SSE stream must not be
      // collected before it is passed on.
      { cf: { cacheTtl: 0, cacheEverything: false } },
    );

    const out = new Headers(upstream.headers);
    if (isStream) {
      out.set("Cache-Control", "no-cache, no-transform");
      out.set("X-Accel-Buffering", "no");
    }

    // The body is passed through as a stream rather than awaited, so SSE
    // events reach the browser as the graph emits them.
    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: out,
    });
  },
};
