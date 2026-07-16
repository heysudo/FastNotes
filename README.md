# FastNotes

Self-hosted, zero-knowledge encrypted notes with a Google Keep-style masonry
board, markdown everywhere, image covers, and optional AI-generated cover art.
One Go binary, one Docker container, loads instantly.

## Install (one command)

```sh
curl -fsSL https://raw.githubusercontent.com/heysudo/FastNotes/main/install.sh | sh
```

Requirements: a Linux server with Docker + Compose v2. The installer asks
whether you want bundled HTTPS (Caddy + your domain) or a local port behind
your own reverse proxy, then builds and starts everything. On first visit you
create a master password — **it is unrecoverable by design**.

## Features

- **Keep-style board** — masonry grid, pinned/others sections, note colors,
  instant client-side search, quick-add bar.
- **Markdown notes** — right-sidebar editor with rendered view, tappable
  `- [ ]` checklists, tables, code blocks. Titles in Noto Serif, body in Noto Sans.
- **Image covers** — attach or paste an image and it becomes the note's card
  cover; Notion-style change/remove controls.
- **Fast** — local-first: all (encrypted) notes are cached in IndexedDB, so the
  board paints from local data in ~200 ms and syncs diffs in the background.
  Edits autosave continuously (300 ms debounce, forced save at least every 5 s).
- **Offline** — a service worker caches the app shell and edits queue in an
  IndexedDB op-log, so you can read and edit with no connection; everything
  syncs when you're back online. Unlock works offline too.
- **Encrypted, zero-knowledge** — see below.
- **Auto-lock** — keys are wiped after 2 minutes of the tab not being active,
  and never persist to disk. Encrypted-backup download button included.

## Security model

- Master password → PBKDF2-SHA256 (600k iterations) → HKDF → AES-256-GCM key,
  all in the browser via Web Crypto. The password and key never leave the tab's
  memory.
- Every note and image is encrypted client-side. The server stores ciphertext,
  random IVs, and timestamps only — `strings` on the database yields nothing.
- API access requires a token derived from the password (separate HKDF branch);
  the server stores only its SHA-256 and rate-limits failures (10 / 5 min / IP).
- Serve over HTTPS: Web Crypto requires a secure context, and you should not
  ship ciphertext over plain HTTP anyway.
- **AI covers are the one documented exception**: when enabled and a note has
  no image, that note's title/text is sent (transiently, never stored) to your
  configured LLM to write an image prompt. Don't enable it if that trade-off
  isn't acceptable for your notes.

## AI cover generation (optional, BYOK)

Add any one key to `.env` and restart (`docker compose up -d`):

| Provider | Key(s) | LLM (prompt) | Image |
|---|---|---|---|
| OpenAI | `OPENAI_API_KEY` | `gpt-4o-mini` | `gpt-image-1` |
| Gemini | `GEMINI_API_KEY` | `gemini-2.5-flash` | `gemini-2.5-flash-image` |
| Anthropic | `ANTHROPIC_API_KEY` | `claude-haiku-4-5` | — (pair with an image provider) |
| Higgsfield | `HF_API_KEY` + `HF_API_SECRET` | — (pair with an LLM provider) | GPT Image via Higgsfield |

Mix and match with `LLM_PROVIDER` / `IMAGE_PROVIDER`, override models with
`LLM_MODEL` / `IMAGE_MODEL`. A single OpenAI or Gemini key covers both steps.
Notes that mention a brand get a flat logo-on-brand-color cover; everything
else gets a minimal icon-style cover. Auto-generates once per note ~4 s after
you stop typing; the ✨ button in the editor regenerates on demand.

<details>
<summary>Advanced: image generation through a Claude subscription + Higgsfield MCP (no image API key)</summary>

The `worker` compose profile runs a sidecar with Claude Code that drives the
Higgsfield MCP connector. Start with `--profile worker`, set
`AI_WORKER_URL=http://fastnotes-ai:7777`, then do the one-time MCP OAuth:

```sh
docker exec -it fastnotes-ai claude mcp add --transport http --scope user higgsfield https://mcp.higgsfield.ai/mcp
docker exec -it fastnotes-ai claude   # then: /mcp -> higgsfield -> Authenticate
```

The OAuth callback listens on the container's port 8080, published loopback-only
as `127.0.0.1:18081` — from your workstation:
`ssh -L 8080:127.0.0.1:18081 you@server`, then open the printed URL in your
browser. Slower (~30–60 s/cover) and the token can occasionally need re-auth;
a direct image API key is the smoother path.
</details>

## Deployment layouts

- `docker-compose.yml` — standalone. Default: app on `127.0.0.1:8484`.
  `COMPOSE_PROFILES=caddy DOMAIN=notes.example.com docker compose up -d --build`
  adds bundled auto-HTTPS.
- `docker-compose.npm.yml` — join an existing reverse-proxy docker network
  (nginx-proxy-manager, traefik, ...): set `PROXY_NETWORK` in `.env`, point your
  proxy at container `fastnotes:8000` with websockets enabled.

## Operations

```sh
docker compose up -d --build   # update after a git pull
docker logs fastnotes          # server logs
./data/                        # the encrypted database — back this folder up
```

The topbar download button exports an encrypted backup (restorable data with
the same master password). To start over completely, stop the container and
delete `data/`.

## Architecture

`server/` is a single Go binary (net/http + bbolt) that embeds the frontend —
the Docker image is ~9 MB from scratch. `web/` is dependency-free vanilla JS
(marked.js + DOMPurify vendored for markdown) with a hand-rolled shortest-column
masonry. No CDN calls, no telemetry, no analytics. All API responses are
ciphertext; delta sync via `GET /api/notes?since=<ms>`.

## License

MIT
