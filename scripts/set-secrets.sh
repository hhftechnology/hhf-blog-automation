#!/usr/bin/env bash
# Set the GitHub Actions secrets for this repo from WSL.
# Usage: scripts/set-secrets.sh [owner/repo]
# Each value is read with hidden input and piped to gh over stdin, so it never
# appears in shell history, the process list or a file. Press Enter to skip one.
set -euo pipefail

REPO="${1:-hhftechnology/hhf-blog-automation}"

if command -v gh >/dev/null 2>&1; then
  GH=(gh)
elif [ -x "/mnt/c/Program Files/GitHub CLI/gh.exe" ]; then
  GH=("/mnt/c/Program Files/GitHub CLI/gh.exe")
else
  echo "GitHub CLI not found. Install gh or the Windows GitHub CLI." >&2
  exit 1
fi

"${GH[@]}" auth status >/dev/null 2>&1 || { echo "Run: gh auth login" >&2; exit 1; }
"${GH[@]}" repo view "$REPO" >/dev/null 2>&1 || { echo "Repo $REPO not found or no access." >&2; exit 1; }

set_secret() {
  local name="$1" required="$2" value=""
  if [ "$name" = "DISCOURSE_URL" ]; then
    read -r -p "$name [https://forum.hhf.technology]: " value
    value="${value:-https://forum.hhf.technology}"
  elif [ "$name" = "DISCOURSE_API_USERNAME" ]; then
    read -r -p "$name (required): " value
  else
    read -r -s -p "$name ($required, input hidden): " value
    echo
  fi
  if [ -z "$value" ]; then
    [ "$required" = "required" ] && echo "  skipped (required: workflows will fail until it is set)" || echo "  skipped"
    return
  fi
  printf '%s' "$value" | "${GH[@]}" secret set "$name" -R "$REPO" >/dev/null
  echo "  set"
  value=""
}

echo "Secrets for $REPO"
set_secret DISCOURSE_URL required
set_secret DISCOURSE_API_KEY required
set_secret DISCOURSE_API_USERNAME required
set_secret GEMINI_API_KEY optional
set_secret NVD_API_KEY optional
set_secret OTX_KEY optional
set_secret ABUSECH_AUTH_KEY optional

echo
echo "Optional repository variables (Settings > Variables): BLOG_URL, PAGES_URL, BLOG_DRAFTS_CATEGORY_ID"
"${GH[@]}" secret list -R "$REPO"
