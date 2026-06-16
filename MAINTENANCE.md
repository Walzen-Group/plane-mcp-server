# Fork maintenance runbook

How this fork of `makeplane/plane-mcp-server` stays in sync with upstream while
keeping our changes (the GHCR image build + the **Authentik OIDC connector** for
self-hosted Plane), how the image is rebuilt, and what to do when a workflow
goes red. **You only need to read the section you're in trouble with**;
everything that works is automated.

> **Fork model:** unlike the `plane` fork (a single patch rebased onto a named
> branch), this fork keeps its commits **directly on `main`** and **merges**
> upstream in. History is preserved; nothing force-pushes. Our changes are a
> small stack on top of upstream `main`:
>
> - `feat: docker image build and ghcr push`
> - `feat(auth): Authentik OIDC connector for self-hosted Plane web chat`

---

## 1. What's automated (the "happy path")

Workflows in `.github/workflows/`:

| Workflow | Runs when | What it does |
| --- | --- | --- |
| **`sync-upstream.yml`** | Mondays 06:00 UTC + manual dispatch | `git fetch upstream main` → `git merge --no-edit upstream/main` into `main` → `git push origin main`. On conflict the job fails (and can ping a Claude routine — §3.3). |
| **`docker-publish.yml`** | Push to `main` + manual dispatch | Builds the server image → pushes to `ghcr.io/walzen-group/plane-mcp-server` (`latest` + tags). |
| **`build-branch.yml`** | (per its own triggers) | Branch image builds. |
| **`publish-pypi.yml`** | (per its own triggers) | PyPI publish (upstream's; not used by our deploy). |

If nothing conflicts, you do nothing: a green sync run every Monday, and — **if
you wire a PAT (see §5)** — a green image build after it.

⚠️ **One caveat by default:** the sync pushes with the built-in `GITHUB_TOKEN`,
and GitHub does **not** trigger other workflows from a `GITHUB_TOKEN` push. So a
successful auto-sync **won't** auto-rebuild the image until you either push
manually, **Run workflow** on `docker-publish.yml`, or switch the sync to a PAT
(§5).

---

## 2. Deploying a new build

The server runs as the `plane-mcp` service in your Plane compose stack
(`compose-files/compose/plane/`). To pick up a fresh image:

```bash
# on the prod host, in the Plane stack dir
docker compose pull plane-mcp
docker compose up -d plane-mcp
docker compose logs -f plane-mcp        # confirm it boots (Authentik OIDC mode)
```

Which build:
- **`MCP_IMAGE_TAG=latest`** (default) — rolls forward to the last image built.
- **`MCP_IMAGE_TAG=<short-sha>`** — pin a specific build (find tags in
  **GitHub → Packages → plane-mcp-server**). Recommended for real prod.

Linked PATs and OAuth state live in the `plane-mcp-redis` volume — they survive
restarts as long as `MCP_PAT_ENCRYPTION_KEY` is unchanged.

---

## 3. When `sync-upstream` fails (merge conflict)

You'll get a failed-run email. 99% of the time it's a **merge conflict** because
upstream changed a file our changes also touch. Fix locally:

```bash
# 1. Match the remote
git checkout main
git fetch origin && git reset --hard origin/main

# 2. Ensure upstream exists
git remote -v   # if no 'upstream':
# git remote add upstream https://github.com/makeplane/plane-mcp-server.git

# 3. Replay the merge the workflow tried
git fetch upstream main
git merge upstream/main
```

Our changes are **mostly additive** (new modules + new env-gated code paths), so
most conflicts resolve by **keeping both sides**. The files most likely to
conflict, and how:

| File | What our changes add | How to resolve |
| --- | --- | --- |
| `plane_mcp/__main__.py` | HTTP-mode provider selection (Authentik → Plane-Cloud → header-only), the provision-routes mount, and a variadic `combined_lifespan` | Keep both. If upstream restructured the HTTP mounting, re-apply our Authentik branch + provision mount into the new shape. |
| `plane_mcp/client.py` | The `authentik_oidc` branch in `get_plane_client_context()` + `provision_url()` / `plane_pat_create_url()` helpers | Keep both. If upstream changed `get_plane_client_context`'s signature/flow, re-thread our branch in. |
| `plane_mcp/server.py` | `get_authentik_oauth_mcp()` factory + `_public_base_url()` | Keep both. |
| `plane_mcp/auth/__init__.py` | Exports for the Authentik provider/verifier | Keep both. |
| `docker-compose.yml` | Rewritten for Authentik + PAT modes | Prefer **our** version; fold in any genuinely new upstream service/env. |
| `README.md`, `.env.test` | Added "Authentik / web connector" sections | Keep both. |
| `Dockerfile`, `pyproject.toml`, `uv.lock` | (unchanged by us) | Take **upstream**. |

**New files never conflict** (git just keeps them): `plane_mcp/auth/authentik_oidc_provider.py`,
`plane_mcp/pat_store.py`, `plane_mcp/provisioning.py`, `tests/test_authentik_provider.py`,
`tests/test_client_context.py`, `tests/test_pat_store.py`, `tests/test_provisioning.py`,
`docs/authentik-setup.md`.

After resolving:

```bash
git add -A
git commit --no-edit          # completes the merge commit

# Sanity-check before pushing (offline, no live Plane/Authentik needed)
uvx ruff check plane_mcp/
uvx --with-editable . --with pytest pytest -q --ignore=tests/test_integration.py

git push origin main
```

### 3.1 What if upstream actually broke our integration?

If a thing our code depends on was **renamed/deleted/re-signatured** (e.g.
`get_plane_client_context`, the FastMCP auth provider wiring, or the tool
registration), the merge may apply but the checks above fail. Treat it as a
small refactor:

- Read the upstream commit: `git log upstream/main -- <path>`.
- Adapt our additions to the new shape.
- Re-run the checks, then commit + push.

If you can't fix it right away, **don't push a broken merge** — prod keeps
running the current `:latest`. You can disable the sync workflow temporarily:
GitHub → Actions → "Sync with upstream" → ⋯ → **Disable workflow**.

### 3.2 Abort and start over

```bash
git merge --abort
git fetch origin && git reset --hard origin/main
```

### 3.3 Auto-resolution with a Claude routine (optional, opt-in)

A Claude routine (on your Claude subscription, not the paid API) is triggered
**directly by the failing `sync-upstream` workflow** via an API webhook — fires
within seconds, no polling. It attempts the merge resolution following §3,
opens a **PR against `main`** (never pushes to `main` directly), or opens an
issue if it can't resolve cleanly.

```
sync-upstream.yml fails ──curl POST──▶ Claude routine webhook
                                            │
                                            ▼
                               Claude clones, merges, resolves
                               conflicts, opens PR / issue
```

**To enable:**

1. **Install the Claude GitHub App** on `walzen-group/plane-mcp-server`
   (github.com/apps/claude). This authenticates the routine's `git clone` and
   `git push` (to `claude/`-prefixed branches) through Claude's GitHub proxy —
   **no PAT needed** — and is also what the optional "Auto-fix pull requests"
   toggle relies on.

2. **Create the routine in Claude** (Routines → New → trigger: **API**). Paste
   the prompt block below, make sure it's connected to GitHub (the App from
   step 1), and optionally flip on **Auto-fix pull requests** so Claude also
   tends CI failures / review comments on the PRs it opens. **No environment
   variable / PAT is required** — the prompt clones, pushes a `claude/…` branch,
   and opens the PR through the built-in GitHub integration, not the `gh` CLI.
   Saving the routine gives you a **webhook URL** with an embedded auth token.
   - *Only* if you change the prompt to call the `gh` CLI directly (for a
     subcommand the built-in tools don't cover) would you need to `apt install
     gh` in a setup script and add `GH_TOKEN=github_pat_…` as an env var on the
     routine's cloud environment (a fine-grained, minimally-scoped PAT). Routine
     env vars are **not encrypted at rest**, so scope it tightly and rotate it.

3. **Store the webhook URL as a repo secret**: Settings → Secrets and variables
   → Actions → New repository secret → name `CLAUDE_ROUTINE_WEBHOOK`, value =
   the webhook URL.

The workflow's final step already POSTs to `${CLAUDE_ROUTINE_WEBHOOK}` on
failure, gated by `env.CLAUDE_ROUTINE_WEBHOOK != ''` — a no-op until you set the
secret, and it just works once you do.

**Routine prompt (paste into the routine's prompt field):**

```
The "Sync with upstream" workflow on $repo failed (merge conflict).
Webhook payload (in $1 or your runtime's payload variable):
  {event, repo, branch, upstream_branch, run_url}

Your job: attempt the merge resolution and open a PR. Use your built-in GitHub
integration for clone / push / PR creation — the `gh` CLI is NOT installed, so
do not call it. Push only to a claude/ branch; never to ${branch} directly.

1. Clone and check out the target branch (the GitHub proxy authenticates this):
     git clone https://github.com/${repo}.git
     cd plane-mcp-server && git checkout ${branch}
2. Add upstream and fetch:
     git remote add upstream https://github.com/makeplane/plane-mcp-server.git
     git fetch upstream ${upstream_branch}
3. Replay the merge:
     git merge upstream/${upstream_branch}    # expect conflicts
4. Resolve following MAINTENANCE.md §3 in that repo. Our changes are mostly
   additive (new modules + env-gated code paths), so most conflicts are
   "keep both sides". New files never conflict. Real restructures (renames,
   deletions, signature changes) need code thinking — see §3.1.
5. Verify before committing (offline; no live Plane/Authentik):
     uvx ruff check plane_mcp/
     uvx --with-editable . --with pytest pytest -q --ignore=tests/test_integration.py
   Both must exit 0.
6. Commit the merge and push to a claude/ branch (allowed by default; the proxy
   authenticates the push — no token needed):
     git add -A && git commit --no-edit
     git checkout -b claude/auto-merge-upstream-$(date +%Y%m%d-%H%M%S)
     git push origin HEAD
7. Open a pull request from that branch against ${branch} using your built-in
   GitHub tools (NOT the gh CLI), titled
     "auto: merge upstream/main (resolve conflicts)"
   with a body listing which files conflicted and how each was resolved, plus a
   link to ${run_url}.

If a conflict is genuinely unresolvable (upstream removed/renamed something our
code depends on), DO NOT guess — abort and open a GitHub issue instead (via your
built-in GitHub tools), titled
   "sync-upstream merge blocked — needs manual resolution"
with a body stating exactly what blocks the merge, which files, what to look at,
and a link to ${run_url}:
     git merge --abort

Never push to ${branch} directly. Only the claude/ branch + PR path.
```

**Trust model:** AI-resolved merges land in a PR titled `auto: merge
upstream/main …`. Skim the diff and merge if it looks right; close it and
resolve manually if not. (And remember §1's caveat: the image only rebuilds on a
PAT-authenticated push or a manual `docker-publish` dispatch.)

**To disable:** delete/rotate the `CLAUDE_ROUTINE_WEBHOOK` secret — the workflow
skips the curl step.

---

## 4. When `docker-publish` fails

Ranked by likelihood:

1. **Real source/lint/test failure** baked into the build. Reproduce locally
   (`uvx ruff check plane_mcp/`, `pytest -q --ignore=tests/test_integration.py`),
   fix on `main`, push.
2. **GHCR push 403** — `GITHUB_TOKEN` lacks `packages: write`, or it's the first
   push to a new package name. Fix: **Settings → Actions → General → Workflow
   permissions → Read and write**, and/or **Packages → plane-mcp-server →
   Package settings → Manage Actions access → add the repo with Write**.
3. **Dockerfile drift** — upstream moved/renamed the `Dockerfile`. Update the
   build context in `docker-publish.yml`.

Find the failing step under the **Actions** tab → the red run.

---

## 5. Making the image auto-rebuild after a sync (optional)

By default the sync push uses `GITHUB_TOKEN`, which does **not** trigger
`docker-publish.yml`. To get an automatic rebuild after each sync, give the sync
workflow a PAT:

1. Create a fine-grained PAT (repo `walzen-group/plane-mcp-server`, `Contents:
   read/write`, `Workflows: read/write`), store it as a repo secret, e.g.
   `SYNC_PAT`.
2. In `sync-upstream.yml`, change the checkout `token:` from
   `${{ secrets.GITHUB_TOKEN }}` to `${{ secrets.SYNC_PAT }}`.

Otherwise just **Run workflow** on `docker-publish.yml` (or push any commit)
when you want a new image.

---

## 6. Reducing email noise

Same options as the `plane` fork: GitHub personal **Settings → Notifications →
Actions** (only personally-triggered failures), a Gmail filter for
`from:notifications@github.com`, or set this repo's watch level to "Ignore" and
check the Actions tab.

---

## Reference: where things live

| Concern | Where |
| --- | --- |
| Upstream sync (merge) | `.github/workflows/sync-upstream.yml` |
| Image build & push | `.github/workflows/docker-publish.yml` |
| Our changes | commits on `main` (GHCR build + Authentik OIDC connector) |
| Connector setup guide | `docs/authentik-setup.md` |
| Deploy compose | `compose-files/compose/plane/` (`plane-mcp` + `plane-mcp-redis`) |
| Published image | `ghcr.io/walzen-group/plane-mcp-server` |
| Build/plan notes | `.codex/` (local only; not required at runtime) |
