#!/bin/sh
# FastNotes one-command installer.
#   curl -fsSL https://raw.githubusercontent.com/heysudo/FastNotes/main/install.sh | sh
# Interactive prompts read from /dev/tty so the pipe-to-sh pattern works.
set -eu

REPO="https://github.com/heysudo/FastNotes"
DIR="${FASTNOTES_DIR:-$HOME/fastnotes}"

say() { printf '\033[1;33m==>\033[0m %s\n' "$*"; }
ask() { # ask "question" "default"
  printf '%s [%s]: ' "$1" "$2" > /dev/tty
  read -r a < /dev/tty || a=""
  [ -n "$a" ] && printf '%s' "$a" || printf '%s' "$2"
}

command -v docker >/dev/null 2>&1 || { echo "ERROR: docker is required — https://docs.docker.com/engine/install/"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "ERROR: docker compose v2 is required"; exit 1; }

say "Fetching FastNotes into $DIR"
if [ -d "$DIR/.git" ]; then
  git -C "$DIR" pull --ff-only
elif command -v git >/dev/null 2>&1; then
  git clone --depth 1 "$REPO" "$DIR"
else
  mkdir -p "$DIR"
  curl -fsSL "$REPO/archive/refs/heads/main.tar.gz" | tar xz -C "$DIR" --strip-components=1
fi
cd "$DIR"
[ -f .env ] || cp .env.example .env

say "FastNotes setup"
MODE=$(ask "Serve mode: 1 = bundled HTTPS via Caddy (needs a domain pointing here), 2 = local port behind your own reverse proxy" "2")

PROFILES=""
if [ "$MODE" = "1" ]; then
  DOMAIN=$(ask "Domain for FastNotes (DNS A record must already point to this server)" "notes.example.com")
  grep -q '^DOMAIN=' .env && sed -i "s|^DOMAIN=.*|DOMAIN=$DOMAIN|" .env || echo "DOMAIN=$DOMAIN" >> .env
  PROFILES="caddy"
else
  PORT=$(ask "Local port to serve on (127.0.0.1)" "8484")
  grep -q '^FN_PORT=' .env && sed -i "s|^FN_PORT=.*|FN_PORT=$PORT|" .env || echo "FN_PORT=$PORT" >> .env
fi

if [ "$(ask "Enable AI cover images? Bring your own key: anthropic / openai / gemini / higgsfield (y/N)" "n")" = "y" ]; then
  echo "Edit $DIR/.env afterwards and set your API key(s):"
  echo "  ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY or HF_API_KEY+HF_API_SECRET"
  echo "One key is enough if the provider supports both text and images (openai, gemini)."
fi

say "Building and starting (first build takes a couple of minutes)"
if [ -n "$PROFILES" ]; then
  COMPOSE_PROFILES="$PROFILES" docker compose up -d --build
else
  docker compose up -d --build
fi

say "Done."
if [ "$MODE" = "1" ]; then
  echo "Open https://$DOMAIN — on first visit you'll create your master password."
else
  echo "FastNotes is on 127.0.0.1:${PORT:-8484}. Point your reverse proxy at it (websockets on),"
  echo "then open it via HTTPS — the crypto requires a secure context (https:// or localhost)."
fi
echo "IMPORTANT: your master password is unrecoverable by design. The encrypted database"
echo "lives in $DIR/data/ — back that folder up."
