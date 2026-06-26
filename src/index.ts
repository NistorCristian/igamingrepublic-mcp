import { OAuthProvider, type OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { defaultHandler } from "./authorize";

/**
 * Worker bindings. `wrangler types` also generates worker-configuration.d.ts,
 * but we declare Env explicitly so the source is self-documenting.
 */
export interface Env {
  /** KV namespace used by the OAuth provider for clients / grants / tokens. */
  OAUTH_KV: KVNamespace;

  // --- vars (wrangler.jsonc) ---
  /** Upstream WordPress mcp-adapter Streamable HTTP endpoint. */
  WP_MCP_URL: string;

  // --- secrets (`wrangler secret put`) ---
  /** Shared password checked by the /authorize consent screen. */
  LOGIN_PASSWORD: string;
  /** WordPress username of the dedicated Editor-role user. */
  WP_APP_USER: string;
  /** That user's WordPress Application Password. */
  WP_APP_PASSWORD: string;

  /** Injected by the OAuth provider so handlers can call its helpers. */
  OAUTH_PROVIDER: OAuthHelpers;
}

/** Grant context attached at consent time and surfaced as ctx.props. */
export interface Props {
  login: string;
  [key: string]: unknown;
}

/** Request headers forwarded claude.ai -> WordPress (lower-case for lookup). */
const FORWARD_REQUEST_HEADERS = [
  "content-type",
  "accept",
  "mcp-session-id",
  "mcp-protocol-version",
  "last-event-id",
] as const;

/** Response headers forwarded WordPress -> claude.ai. */
const FORWARD_RESPONSE_HEADERS = [
  "content-type",
  "mcp-session-id",
  "mcp-protocol-version",
  "cache-control",
] as const;

/**
 * API handler. Reached ONLY after the OAuth provider has validated a
 * worker-issued Bearer token, so any request here is authenticated.
 *
 * This is a plain fetch handler (no McpAgent / Durable Object): the worker is a
 * stateless reverse proxy and WordPress's HttpTransport owns the MCP session.
 */
const proxyHandler = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Presence of ctx.props proves the token was valid; we don't otherwise need it.
    void (ctx as ExecutionContext & { props?: Props }).props;

    if (request.method === "OPTIONS") {
      return preflight(request);
    }
    if (request.method !== "GET" && request.method !== "POST" && request.method !== "DELETE") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    // Copy through only the MCP-relevant request headers.
    const outHeaders = new Headers();
    for (const name of FORWARD_REQUEST_HEADERS) {
      const value = request.headers.get(name);
      if (value !== null) outHeaders.set(name, value);
    }

    // Strip the inbound worker token and inject WordPress Basic Auth built from
    // the Application Password. (Never forward claude.ai's Bearer upstream.)
    outHeaders.delete("authorization");
    outHeaders.set(
      "authorization",
      "Basic " + base64(`${env.WP_APP_USER}:${env.WP_APP_PASSWORD}`),
    );

    // Buffer the (small) JSON-RPC request body rather than streaming it. This
    // avoids duplex/half-stream pitfalls and "body already used" errors if the
    // OAuth layer touched the request. The RESPONSE is still streamed (for SSE).
    let body: ArrayBuffer | undefined;
    if (request.method !== "GET") {
      const buf = await request.arrayBuffer();
      body = buf.byteLength > 0 ? buf : undefined;
    }

    // Peek at the JSON-RPC method/id purely for diagnostic logging.
    let rpc = "(no body)";
    if (body) {
      try {
        const p = JSON.parse(new TextDecoder().decode(body));
        rpc = Array.isArray(p)
          ? `batch[${p.length}]`
          : `${p?.method ?? "?"} id=${JSON.stringify(p?.id)}`;
      } catch {
        rpc = "<non-json>";
      }
    }

    let upstream: Response;
    try {
      upstream = await fetch(env.WP_MCP_URL, {
        method: request.method,
        headers: outHeaders,
        body,
        redirect: "manual",
      });
    } catch (err) {
      console.error(`proxy: upstream fetch threw for ${request.method} ${rpc}`, {
        error: err instanceof Error ? err.message : String(err),
      });
      return jsonRpcError(-32001, "Upstream request to WordPress failed");
    }

    // Visible in `wrangler tail` / dashboard Logs so we can see the real status.
    console.log(
      `proxy: ${request.method} [${rpc}] -> ${upstream.status} ` +
        `ct=${upstream.headers.get("content-type") ?? "?"} ` +
        `sid=${upstream.headers.get("mcp-session-id") ?? "-"}`,
    );

    // Stream the response body straight back — identical for JSON and text/event-stream.
    const respHeaders = new Headers();
    for (const name of FORWARD_RESPONSE_HEADERS) {
      const value = upstream.headers.get(name);
      if (value !== null) respHeaders.set(name, value);
    }
    applyCors(request, respHeaders);

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: respHeaders,
    });
  },
};

/** base64 of a UTF-8 string, Workers-safe. */
function base64(input: string): string {
  return btoa(String.fromCharCode(...new TextEncoder().encode(input)));
}

/** Minimal JSON-RPC error envelope for proxy-level failures. */
function jsonRpcError(code: number, message: string): Response {
  return new Response(
    JSON.stringify({ jsonrpc: "2.0", error: { code, message }, id: null }),
    { status: 502, headers: { "content-type": "application/json" } },
  );
}

function preflight(request: Request): Response {
  const headers = new Headers();
  applyCors(request, headers);
  headers.set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  headers.set(
    "Access-Control-Allow-Headers",
    "Authorization, Content-Type, Accept, Mcp-Session-Id, MCP-Protocol-Version, Last-Event-Id",
  );
  headers.set("Access-Control-Expose-Headers", "Mcp-Session-Id, MCP-Protocol-Version");
  headers.set("Access-Control-Max-Age", "86400");
  return new Response(null, { status: 204, headers });
}

function applyCors(request: Request, headers: Headers): void {
  const origin = request.headers.get("origin");
  headers.set("Access-Control-Allow-Origin", origin ?? "*");
  headers.set("Vary", "Origin");
}

/**
 * The OAuthProvider wraps everything:
 *  - apiRoute "/mcp"                      -> proxyHandler (token-protected)
 *  - /authorize and other paths          -> defaultHandler (consent UI)
 *  - /token, /register, /.well-known/*   -> implemented by the library
 */
export default new OAuthProvider({
  apiRoute: "/mcp",
  apiHandler: proxyHandler,
  defaultHandler: defaultHandler,
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/token",
  clientRegistrationEndpoint: "/register",
  scopesSupported: ["mcp"],
  accessTokenTTL: 3600,
});
