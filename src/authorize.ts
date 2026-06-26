import type { Env, Props } from "./index";
import { loginPage } from "./html";

/**
 * defaultHandler: serves the password-gated /authorize consent screen and a
 * tiny landing route. Everything else (token, register, discovery docs) is
 * handled by the OAuthProvider itself.
 */
export const defaultHandler = {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/authorize") {
      if (request.method === "GET") return renderLogin(request, env);
      if (request.method === "POST") return handleLogin(request, env);
      return new Response("Method Not Allowed", { status: 405 });
    }

    if (url.pathname === "/" && request.method === "GET") {
      return new Response("igamingrepublic-mcp: OK", {
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }

    return new Response("Not found", { status: 404 });
  },
};

/**
 * GET /authorize — validate the inbound OAuth request, then render the login
 * form. The raw OAuth query string is round-tripped in a hidden field so the
 * POST can reconstruct and re-parse it.
 */
async function renderLogin(request: Request, env: Env): Promise<Response> {
  // Validates client_id / redirect_uri / PKCE / state (throws on bad input).
  const oauthReq = await env.OAUTH_PROVIDER.parseAuthRequest(request);
  const client = await env.OAUTH_PROVIDER.lookupClient(oauthReq.clientId);

  const csrf = crypto.randomUUID();
  const url = new URL(request.url);

  const html = loginPage({
    clientName: client?.clientName ?? oauthReq.clientId,
    oauthQuery: url.search, // ?response_type=...&client_id=...&code_challenge=...&state=...
    csrf,
    error: null,
  });

  return new Response(html, {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "set-cookie": `csrf=${csrf}; HttpOnly; Secure; SameSite=Lax; Path=/authorize; Max-Age=600`,
      "cache-control": "no-store",
    },
  });
}

/**
 * POST /authorize — verify CSRF + the shared password (timing-safe), then
 * complete the grant and redirect back to the OAuth client.
 */
async function handleLogin(request: Request, env: Env): Promise<Response> {
  const form = await request.formData();
  const submittedPassword = String(form.get("password") ?? "");
  const oauthQuery = String(form.get("oauth_query") ?? "");
  const formCsrf = String(form.get("csrf") ?? "");
  const cookieCsrf = readCookie(request, "csrf");

  // CSRF: double-submit cookie check.
  if (!cookieCsrf || !timingSafeEqual(formCsrf, cookieCsrf)) {
    return new Response("Bad Request (CSRF)", { status: 400 });
  }

  // Reconstruct the original OAuth request from the round-tripped query string.
  const rebuilt = new Request(new URL(oauthQuery, request.url).toString(), { method: "GET" });
  const oauthReq = await env.OAUTH_PROVIDER.parseAuthRequest(rebuilt);

  // Timing-safe password compare against the Worker secret.
  if (!timingSafeEqual(submittedPassword, env.LOGIN_PASSWORD)) {
    const client = await env.OAUTH_PROVIDER.lookupClient(oauthReq.clientId);
    const html = loginPage({
      clientName: client?.clientName ?? oauthReq.clientId,
      oauthQuery,
      csrf: formCsrf,
      error: "Incorrect password.",
    });
    return new Response(html, {
      status: 401,
      headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
    });
  }

  const props: Props = { login: "owner" };

  const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
    request: oauthReq,
    userId: "owner", // single-user: one stable identity
    scope: oauthReq.scope ?? ["mcp"],
    metadata: { loginAt: Date.now() },
    props,
  });

  return Response.redirect(redirectTo, 302);
}

function readCookie(request: Request, name: string): string | null {
  const cookie = request.headers.get("cookie") ?? "";
  for (const part of cookie.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
  return null;
}

/** Constant-time string comparison to avoid leaking the password via timing. */
function timingSafeEqual(a: string, b: string): boolean {
  const ea = new TextEncoder().encode(a);
  const eb = new TextEncoder().encode(b);
  if (ea.length !== eb.length) {
    let diff = 1;
    const max = Math.max(ea.length, eb.length);
    for (let i = 0; i < max; i++) diff |= (ea[i] ?? 0) ^ (eb[i] ?? 0);
    return false;
  }
  let diff = 0;
  for (let i = 0; i < ea.length; i++) diff |= ea[i] ^ eb[i];
  return diff === 0;
}
