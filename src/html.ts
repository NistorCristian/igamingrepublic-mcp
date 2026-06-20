export interface LoginPageOpts {
  clientName: string;
  oauthQuery: string;
  csrf: string;
  error: string | null;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function loginPage(o: LoginPageOpts): string {
  const err = o.error ? `<p class="err">${escapeHtml(o.error)}</p>` : "";
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize ${escapeHtml(o.clientName)}</title>
<style>
  body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:grid;place-items:center;height:100vh;margin:0}
  .card{background:#1e293b;padding:2rem;border-radius:12px;width:min(92vw,360px);box-shadow:0 10px 30px rgba(0,0,0,.4)}
  h1{font-size:1.1rem;margin:0 0 .25rem}
  p.sub{color:#94a3b8;margin:0 0 1.25rem;font-size:.9rem}
  label{display:block;font-size:.85rem;margin:0 0 .35rem;color:#cbd5e1}
  input[type=password]{width:100%;box-sizing:border-box;padding:.7rem;border-radius:8px;border:1px solid #334155;background:#0f172a;color:#fff}
  button{margin-top:1rem;width:100%;padding:.7rem;border:0;border-radius:8px;background:#3b82f6;color:#fff;font-weight:600;cursor:pointer}
  .err{color:#f87171;font-size:.85rem;margin:.5rem 0 0}
</style></head>
<body>
  <form class="card" method="POST" action="/authorize">
    <h1>Connect ${escapeHtml(o.clientName)}</h1>
    <p class="sub">Enter the access password to authorize this connection to igamingrepublic.com.</p>
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" autofocus required>
    ${err}
    <input type="hidden" name="oauth_query" value="${escapeHtml(o.oauthQuery)}">
    <input type="hidden" name="csrf" value="${escapeHtml(o.csrf)}">
    <button type="submit">Authorize</button>
  </form>
</body></html>`;
}
