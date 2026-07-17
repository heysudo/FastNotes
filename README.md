<div align="center">

# ⚡ FastNotes

**A self-hosted, zero-knowledge encrypted notes app — Google Keep's speed and layout, with your keys and your server.**

Masonry board · Markdown everywhere · Image covers · AI-generated cover art · Offline-first · End-to-end encrypted

```
curl -fsSL https://raw.githubusercontent.com/heysudo/FastNotes/main/install.sh | sh
```

<sub>Go binary · ~9 MB Docker image · no CDN · no telemetry · MIT licensed</sub>

</div>

---

## Why FastNotes

Your notes are encrypted in your browser before they ever reach the server. The
master password never leaves the tab; the server only ever sees ciphertext.
Running `strings` on the database returns nothing. It loads instantly because
every (encrypted) note is cached locally, and it keeps working — read and
write — with no connection at all.

|  | |
|---|---|
| 🔒 **Zero-knowledge** | AES-256-GCM with a key derived from your master password via PBKDF2-SHA256 (600k iterations), all client-side. The server stores only ciphertext, random IVs, and timestamps. |
| 🗂️ **Keep-style board** | Masonry grid with pinned / others sections, note colors, instant client-side search, and a quick-add bar. |
| ✍️ **Markdown notes** | Right-sidebar editor with live preview, tappable `- [ ]` checklists, tables, and code blocks. Serif titles, native system-ui body text. Full-screen mobile editor. |
| 🖼️ **Image covers** | Attach or paste an image and it becomes the note's card cover, with Notion-style change / remove controls. |
| 🤖 **AI cover art** *(optional)* | Bring your own key (OpenAI, Gemini, Anthropic, or Higgsfield). Notes that mention a brand get a clean logo-on-brand-color cover; everything else gets a minimal icon. |
| ⚡ **Local-first & offline** | Encrypted notes cached in IndexedDB paint the board in ~200 ms; edits queue offline and sync when you reconnect. A service worker caches the app shell so it opens with no network. |
| 🔁 **Real-time, lossless sync** | Changes push to your other open devices in ~0.5 s over SSE. Per-note versioning + 3-way merge means concurrent edits are merged automatically, and genuinely conflicting edits are kept as a *(conflict copy)* — never silently overwritten. |
| 🔐 **Auto-lock** | Keys are wiped from memory after 2 minutes of the tab being inactive, and never persist to disk. |

---

## Installation

### Requirements

- A **Linux server** you control (any VPS or dedicated box — 1 vCPU / 512 MB RAM is plenty).
- **Docker Engine** and the **Docker Compose v2** plugin.
- A **domain name** *(only if you want the bundled automatic-HTTPS option)*.

<details>
<summary><b>Don't have Docker yet? Install it (Ubuntu / Debian)</b></summary>

```bash
# Install Docker Engine + Compose v2 plugin via the official convenience script
curl -fsSL https://get.docker.com | sh

# Allow your user to run docker without sudo (log out / back in afterwards)
sudo usermod -aG docker "$USER"

# Verify — both should print a version
docker --version
docker compose version
```

For other distributions, follow the official guide: <https://docs.docker.com/engine/install/>

</details>

### Step 1 — Run the installer

SSH into your server and run:

```bash
curl -fsSL https://raw.githubusercontent.com/heysudo/FastNotes/main/install.sh | sh
```

The installer clones the repo into `~/fastnotes`, then asks **one question** — how you want to serve it:

<table>
<tr>
<th align="left">Option 1 — Bundled HTTPS (Caddy)</th>
<th align="left">Option 2 — Local port (your own proxy)</th>
</tr>
<tr valign="top">
<td>

Best if this server has **nothing else** on ports 80/443.

You'll be asked for a **domain**. Point its DNS **A record** at the
server's IP first, then Caddy fetches a Let's Encrypt certificate and
serves HTTPS automatically.

```
Serve mode: 1
Domain: notes.example.com
```

</td>
<td>

Best if you **already run** nginx-proxy-manager, Traefik, Caddy, etc.

FastNotes binds to `127.0.0.1:<port>` and you point your existing
reverse proxy at it (enable **WebSocket** support).

```
Serve mode: 2
Local port: 8484
```

</td>
</tr>
</table>

The first build takes a couple of minutes. When it finishes, the installer
prints your URL.

### Step 2 — Create your master password

Open the URL in a browser. On the **first visit** you'll be prompted to create a
master password (minimum 8 characters).

> [!WARNING]
> Your master password **cannot be recovered.** It is the only thing that can
> decrypt your notes — there is no reset, no backdoor, no email recovery, by
> design. Store it in a password manager. The encrypted database lives in
> `~/fastnotes/data/` — back that folder up.

> [!IMPORTANT]
> Always serve FastNotes over **HTTPS** (or `localhost`). Browser Web Crypto —
> the entire encryption layer — only runs in a secure context.

### Step 3 — Updating later

```bash
cd ~/fastnotes
git pull
docker compose up -d --build
```

---

## AI cover generation (optional, bring your own key)

Add **one** API key to `~/fastnotes/.env` and restart with
`docker compose up -d`. The first configured provider is used automatically.

| Provider | Add to `.env` | Writes prompt | Renders image |
|---|---|:---:|:---:|
| **OpenAI** | `OPENAI_API_KEY=sk-…` | `gpt-4o-mini` | `gpt-image-1` |
| **Gemini** | `GEMINI_API_KEY=…` | `gemini-2.5-flash` | `gemini-2.5-flash-image` |
| **Anthropic** | `ANTHROPIC_API_KEY=sk-ant-…` | `claude-haiku-4-5` | *(pair with an image provider)* |
| **Higgsfield** | `HF_API_KEY=…` `HF_API_SECRET=…` | *(pair with an LLM)* | GPT Image via Higgsfield |

A single **OpenAI** or **Gemini** key covers both steps. Force a specific mix
with `LLM_PROVIDER` / `IMAGE_PROVIDER` and override models with `LLM_MODEL` /
`IMAGE_MODEL`. Covers auto-generate once per note ~4 s after you stop typing;
the ✨ button in the editor regenerates on demand.

> [!NOTE]
> AI covers are the **one documented exception** to zero-knowledge: when
> enabled and a note has no image, that note's title and text are sent
> (transiently, never stored) to your chosen LLM to write an image prompt. Leave
> it off if that trade-off isn't right for your notes.

<details>
<summary><b>Advanced: generate images via a Claude subscription + Higgsfield MCP (no image API key)</b></summary>

The `worker` compose profile runs a sidecar with Claude Code that drives the
[Higgsfield MCP](https://mcp.higgsfield.ai) connector — useful if you have a
Higgsfield account but no image API key.

```bash
# start with the worker profile, then set AI_WORKER_URL in .env
docker compose --profile worker up -d --build

# one-time MCP OAuth (the callback listens on the container's port 8080,
# published loopback-only as 127.0.0.1:18081)
docker exec -it fastnotes-ai claude mcp add --transport http --scope user higgsfield https://mcp.higgsfield.ai/mcp
docker exec -it fastnotes-ai claude    # then: /mcp → higgsfield → Authenticate
```

From your workstation, tunnel the callback and open the printed URL:
`ssh -L 8080:127.0.0.1:18081 you@server`. Slower (~30–60 s/cover) and the token
can occasionally need re-auth — a direct image API key is the smoother path.

</details>

---

## Deployment layouts

FastNotes ships two Compose files:

- **`docker-compose.yml`** — standalone. Defaults to `127.0.0.1:8484`. Add
  bundled auto-HTTPS with the `caddy` profile:

  ```bash
  COMPOSE_PROFILES=caddy DOMAIN=notes.example.com docker compose up -d --build
  ```

- **`docker-compose.npm.yml`** — join an **existing** reverse-proxy Docker
  network (nginx-proxy-manager, Traefik, …). Set `PROXY_NETWORK` in `.env`, then
  point your proxy at container `fastnotes` on port `8000` with WebSockets
  enabled:

  ```bash
  docker compose -f docker-compose.npm.yml up -d --build
  ```

---

## Operations

```bash
docker compose up -d --build   # apply an update after `git pull`
docker logs fastnotes          # server logs
```

The topbar **download** button exports an encrypted backup (restorable with the
same master password). To wipe everything and start fresh, stop the container
and delete `~/fastnotes/data/`.

---

## Security model

- **Key derivation** — master password → PBKDF2-SHA256 (600,000 iterations) →
  HKDF → an AES-256-GCM data key and a separate API auth token. The password and
  keys live only in the tab's memory and are wiped on lock.
- **At rest** — every note and image is encrypted client-side. The server (Go +
  [bbolt](https://github.com/etcd-io/bbolt)) persists ciphertext, random IVs, and
  timestamps only.
- **Authentication** — the API token is derived from the password on a separate
  HKDF branch; the server stores only its SHA-256 and rate-limits failed attempts
  (10 per 5 minutes). By default `X-Forwarded-For` is ignored (trusted from no
  one, so it can't be spoofed to evade the limit) and the cap is global — fine
  for a single-master-password app. To get accurate per-client limiting behind a
  proxy, set `TRUSTED_PROXIES` to your proxy's exact address; do **not** trust a
  whole shared Docker subnet, or co-tenant containers could forge the header.
- **First-run protection** — the setup endpoint that registers your master
  password works only once. If that page is reachable from the internet before
  you create your account, set `SETUP_TOKEN` in `.env`; first-run then requires
  it (you're prompted in the browser), preventing a stranger from claiming the
  instance.
- **Transport** — responses carry `HSTS`, a strict `Content-Security-Policy`
  (`script-src 'self'`, no third-party origins), `X-Frame-Options: DENY`, and
  `nosniff`. Always terminate TLS in front of FastNotes.
- **No third parties** — no CDN calls, no analytics, no telemetry. `marked` and
  `DOMPurify` are vendored and kept current. The only outbound requests are the
  optional AI-cover calls you explicitly enable.

---

## Architecture

`server/` is a single Go binary (net/http + bbolt) that embeds the entire
frontend via `go:embed` — the production Docker image is **~9 MB** built `FROM
scratch`. `web/` is dependency-free vanilla JavaScript with a hand-rolled
shortest-column masonry;
[marked.js](https://github.com/markedjs/marked) and
[DOMPurify](https://github.com/cure53/DOMPurify) are vendored locally for safe
markdown rendering.

**Sync.** Notes pull as encrypted deltas via `GET /api/notes?since=<ms>`, and a
lightweight SSE stream (`GET /api/events`) notifies open clients the instant
anything changes so they pull within ~0.5 s. Each note carries a monotonic
version; writes use optimistic concurrency (`base_version`) and the server
rejects a stale write with `409` rather than overwriting. The client then
3-way-merges (diff3) the base, local, and remote versions — a clean merge is
pushed back, an unmergeable one is preserved as a *(conflict copy)*. Offline
edits are held in an IndexedDB op-log and replayed on reconnect. All of this
operates on ciphertext; the server never sees a merge or a plaintext note.

---

## License

[MIT](LICENSE) © 2026 Asis Panda
