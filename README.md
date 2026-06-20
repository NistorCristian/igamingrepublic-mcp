# igamingrepublic-mcp

An OAuth-gated remote **MCP server** running on a single **Cloudflare Worker**. It lets
[claude.ai](https://claude.ai) connect to the WordPress **Abilities API** of
`igamingrepublic` (16 content tools: posts, categories, tags, media, authors).

The Worker is:

- **Its own OAuth 2.1 authorization server** (no third-party identity provider) using
  [`@cloudflare/workers-oauth-provider`](https://github.com/cloudflare/workers-oauth-provider).
  It implements PKCE, Dynamic Client Registration (RFC 7591) and the `.well-known`
  discovery documents that claude.ai needs.
- A **transparent reverse proxy** to the WordPress `mcp-adapter` Streamable HTTP endpoint.
  It does **not** re-implement tools, so any new ability you register in the theme's
  `functions.php` appears in claude.ai automatically.

```
claude.ai ──OAuth 2.1 (PKCE + DCR)──► Cloudflare Worker
                                        • /authorize gated by ONE shared password
                                        • OAUTH_KV stores clients / grants / tokens
                                        │
                                        └─Basic Auth (WP App Password)─► www.igamingrepublic.com
                                                                         /wp-json/mcp/mcp-adapter-default-server
```

## How it works

| Path | Handler | Purpose |
| --- | --- | --- |
| `/mcp` | proxy (token-protected) | Forwards MCP JSON-RPC / SSE to WordPress with Basic Auth injected. |
| `/authorize` | `src/authorize.ts` | Password-gated consent screen → completes the grant. |
| `/token`, `/register`, `/.well-known/*` | library | OAuth token exchange, DCR, discovery metadata. |

Only `/mcp` requires a worker-issued token. Unauthenticated `/mcp` requests get a
`401 WWW-Authenticate`, which bootstraps claude.ai's discovery → register → authorize → token flow.

## Setup

### 1. WordPress (one-time)

1. Create a dedicated **Editor**-role user (e.g. `mcp-bot`). Editor is required so the
   media / delete / edit-others tools work.
2. As that user: **Users → Profile → Application Passwords** → add one named `mcp-worker`
   → copy the generated value (used as `WP_APP_PASSWORD`).

The theme already whitelists the `/wp-json/mcp/` transport; the Application Password
supplies the WP user identity each ability's `permission_callback` checks.

### 2. Deploy the Worker

```bash
npm install
npx wrangler login

# Create the KV namespace and paste the returned id into wrangler.jsonc -> kv_namespaces[0].id
npx wrangler kv namespace create OAUTH_KV

# Secrets (you'll be prompted to paste each value):
npx wrangler secret put LOGIN_PASSWORD     # shared consent-screen password
npx wrangler secret put WP_APP_USER        # e.g. mcp-bot
npx wrangler secret put WP_APP_PASSWORD    # the WP Application Password

npx wrangler types     # optional: generates worker-configuration.d.ts
npx wrangler deploy     # -> https://igamingrepublic-mcp.<subdomain>.workers.dev
```

### 3. Connect from claude.ai

**Settings → Connectors → Add custom connector**, paste:

```
https://igamingrepublic-mcp.<subdomain>.workers.dev/mcp
```

claude.ai self-registers, opens the Worker's `/authorize` page → enter `LOGIN_PASSWORD` →
the 16 WordPress tools appear.

## Local development

```bash
cp .dev.vars.example .dev.vars   # fill in the three secrets
npx wrangler dev                  # http://localhost:8787
```

## Verify

```bash
# Discovery documents return 200 JSON:
curl -s http://localhost:8787/.well-known/oauth-authorization-server | jq .
curl -s http://localhost:8787/.well-known/oauth-protected-resource   | jq .

# Unauthenticated /mcp returns 401 with a WWW-Authenticate header:
curl -i -s -X POST http://localhost:8787/mcp \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | head -n 15

# Full OAuth + tools/list end-to-end (drives the whole flow in a browser):
npx @modelcontextprotocol/inspector
#   Transport = Streamable HTTP, URL = http://localhost:8787/mcp -> Connect
#   -> enter LOGIN_PASSWORD -> List Tools shows the 16 abilities.
```

## Security

Anyone who knows `LOGIN_PASSWORD` obtains **Editor-level** WordPress control through MCP.
Use a strong password and rotate it any time with `npx wrangler secret put LOGIN_PASSWORD`.
The Worker stores no WordPress credentials in code — they live only as Cloudflare secrets.
