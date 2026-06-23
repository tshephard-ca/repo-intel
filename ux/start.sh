#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)

: "${REPOINTEL_DATABASE_URL:=postgres://repointel:repointel@127.0.0.1:15432/repointel}"
: "${REPOINTEL_BASE_URL:=http://127.0.0.1:18101}"
: "${METADATA_COLLECTION_BASE_URL:=http://127.0.0.1:18102}"
: "${REPOINTEL_DEBUG_UI_HOST:=0.0.0.0}"
: "${REPOINTEL_DEBUG_UI_PORT:=18110}"
: "${REPOINTEL_UX_LOG:=/tmp/repointel-ux.log}"

export REPOINTEL_DATABASE_URL
export REPOINTEL_BASE_URL
export METADATA_COLLECTION_BASE_URL
export REPOINTEL_DEBUG_UI_HOST
export REPOINTEL_DEBUG_UI_PORT

cd "$REPO_ROOT"

if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -q ":$REPOINTEL_DEBUG_UI_PORT "; then
  echo "Repointel UX already appears to be listening on port $REPOINTEL_DEBUG_UI_PORT"
  exit 0
fi

setsid -f sh -c 'exec node projects/repointel-metadata-collection/ux/server.mjs >>"$0" 2>&1' "$REPOINTEL_UX_LOG"
echo "Repointel UX started on http://$REPOINTEL_DEBUG_UI_HOST:$REPOINTEL_DEBUG_UI_PORT"
echo "Log: $REPOINTEL_UX_LOG"
