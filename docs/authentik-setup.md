# Self-hosted Plane + Claude.ai web connector (Authentik OIDC)

This guide sets up the Plane MCP server as a **custom connector in Claude.ai web chat**,
against a **self-hosted Plane** instance, for **multiple users**, authenticating through your
org's **Authentik** identity provider.

## Why this mode exists

Claude.ai *web* connectors authenticate **only via OAuth 2.1 + PKCE** — there is no field for a
static API key or header. Self-hosted Plane (Community Edition) can't issue OAuth tokens, so we:

1. authenticate the **user** through Authentik (OIDC), then
2. map that verified identity to the user's own **Plane Personal Access Token (PAT)**, which the
   server uses for all Plane API calls — so every action is attributed to the real user.

Each user links their PAT **once** through a self-service page. After that it's invisible.

> **Don't need web chat?** If your users are on **Claude Desktop / Claude Code / Cursor / VS Code**
> (clients that allow custom headers), you don't need any of this — point them at
> `{host}/http/api-key/mcp` with headers `x-api-key: <plane PAT>` and `x-workspace-slug: <slug>`.
> Authentik mode is specifically for the **web** connector.

## Prerequisites

- A self-hosted Plane instance (API reachable; ideally the web app too).
- An Authentik instance you administer.
- A place to run this server behind **public HTTPS** (a reverse proxy / ingress with TLS).
  OAuth redirects for web chat cannot use `localhost`.
- Redis (strongly recommended) so linked PATs and OAuth state survive restarts.

---

## Step 1 — Create the Authentik provider + application

In Authentik (**Admin interface → Applications**):

1. **Create an OAuth2/OpenID Provider**:
   - **Authorization flow**: your standard `default-provider-authorization-explicit-consent`
     (or implicit-consent) flow.
   - **Client type**: `Confidential`.
   - **Signing key**: select a certificate so ID tokens are signed (RS256) — required; the server
     verifies the ID token against Authentik's JWKS.
   - **Redirect URIs / Origins** — add **both** of these (substitute your public base URL, and your
     `MCP_PATH_PREFIX` if you set one; most deployments leave the prefix empty):
     ```
     https://mcp.example.com/http/auth/callback
     https://mcp.example.com/http/provision/callback
     ```
     - `…/http/auth/callback` — the MCP OAuth callback (Claude.ai web login).
     - `…/http/provision/callback` — the self-service PAT-linking page login.
   - **Scopes**: ensure `openid`, `email`, `profile` are available.
2. **Create an Application** and bind it to that provider. Restrict access with a policy/group if you
   want to control who can use the connector.
3. From the provider page, copy:
   - **Client ID** → `AUTHENTIK_CLIENT_ID`
   - **Client Secret** → `AUTHENTIK_CLIENT_SECRET`
   - **OpenID Configuration URL** → `AUTHENTIK_CONFIG_URL`
     (shape: `https://auth.example.com/application/o/<app-slug>/.well-known/openid-configuration`).
     Alternatively set `AUTHENTIK_BASE_URL` + `AUTHENTIK_APP_SLUG` and the server derives it.

---

## Step 2 — Configure the MCP server

Set these environment variables (see `docker-compose.yml` and `.env.test` for the full list):

| Variable | Example | Notes |
|---|---|---|
| `AUTHENTIK_CONFIG_URL` | `https://auth.example.com/application/o/plane-mcp/.well-known/openid-configuration` | or `AUTHENTIK_BASE_URL` + `AUTHENTIK_APP_SLUG` |
| `AUTHENTIK_CLIENT_ID` | `…` | from Authentik |
| `AUTHENTIK_CLIENT_SECRET` | `…` | from Authentik |
| `MCP_PUBLIC_BASE_URL` | `https://mcp.example.com` | public HTTPS origin of **this** server, no trailing slash |
| `MCP_PAT_ENCRYPTION_KEY` | `openssl rand -base64 48` | **stable** secret; encrypts linked PATs at rest. Changing it orphans all links |
| `PLANE_BASE_URL` | `https://plane.example.com/api` | Plane REST API base |
| `PLANE_WEB_URL` | `https://plane.example.com` | for the "create a PAT" deep link (else derived from `PLANE_BASE_URL`) |
| `PLANE_WORKSPACE_SLUG` | `your-workspace` | default workspace each user can override |
| `REDIS_HOST` / `REDIS_PORT` | `redis` / `6379` | persistence for PAT links + OAuth state |

Optional: `AUTHENTIK_AUDIENCE` (defaults to the client id), `MCP_JWT_SIGNING_KEY` (else derived from
the client secret), `PLANE_INTERNAL_BASE_URL` (in-cluster Plane URL), `MCP_PATH_PREFIX`.

---

## Step 3 — Run it behind public HTTPS

```bash
docker compose up -d        # builds, starts redis + the server on :8211 in `http` mode
```

Front it with your reverse proxy so `https://mcp.example.com` → the container's `:8211`. Verify:

```bash
curl -s https://mcp.example.com/.well-known/oauth-protected-resource/http/mcp | jq .
```

You should get OAuth metadata (not a 404/500). If discovery to Authentik is unreachable at boot, the
server logs a CRITICAL line and falls back to header-auth only — fix connectivity and restart.

---

## Step 4 — Add the connector in Claude.ai

In Claude.ai web → **Settings → Connectors → Add custom connector**:

- **URL**: `https://mcp.example.com/http/mcp`
- Claude redirects you to **Authentik** to log in and consent. After that, the connector shows as
  connected.

---

## Step 5 — Link your Plane account (one time per user)

The first time a user invokes a Plane tool before linking, the tool returns an actionable message
with a link. Or go straight to:

```
https://mcp.example.com/http/provision
```

1. You're sent to Authentik to log in (silent if you already have a session).
2. On the page, click through to create a Plane PAT
   (`https://plane.example.com/settings/profile/api-tokens/`), copy it, paste it back, optionally set
   your workspace slug, and **Link account**.
3. Done — Plane tools now act as **you** in Plane. You can revisit the page to change the workspace or
   **Disconnect**.

---

## How it works (one paragraph)

FastMCP's `OIDCProxy` handles the Claude.ai-facing OAuth (DCR, PKCE, consent) and verifies the
Authentik **ID token** against its JWKS (`verify_id_token=True`, so it works even if Authentik issues
opaque access tokens). The verified identity (`sub`) is mapped to a Plane PAT in a per-user store
(Redis, **Fernet-encrypted at rest**). On each tool call the server looks up that PAT and calls Plane
with it — the Authentik token is **never** sent to Plane. The provision page runs its own short
Authentik session login (signed, `HttpOnly`/`Secure`/`SameSite=Lax` cookie, CSRF-protected POSTs).

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Connector login loops / `redirect_uri` error in Authentik | The two redirect URIs in Step 1 don't exactly match `MCP_PUBLIC_BASE_URL` (+ prefix). |
| First tool call says "account isn't linked" with a relative link | `MCP_PUBLIC_BASE_URL` not set — links can't be absolute. Set it and restart. |
| Links vanish after a restart | No Redis (in-memory store), or `MCP_PAT_ENCRYPTION_KEY` changed/unset. Set both, stably. |
| Server boots but web connector missing; logs show CRITICAL Authentik init failure | Authentik discovery URL unreachable/wrong at boot. Fix connectivity/URL, restart. |
| Tool calls fail with a Plane 401/403 after working before | The user's PAT was revoked/expired in Plane — revisit `/http/provision` and re-link. |
