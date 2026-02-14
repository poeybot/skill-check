#!/usr/bin/env bash
set -euo pipefail

# skill-check enforced installer for ClawHub skills
# Usage:
#   scripts/safe_install.sh <slug> [--version X.Y.Z] [--category 1|2|3|4] [--policy FILE]

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <slug> [--version X.Y.Z] [--category 1|2|3|4] [--policy FILE]"
  exit 2
fi

SLUG="$1"
shift || true

VERSION=""
CATEGORY="2"
POLICY=""
EXTRA_INSTALL_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION="${2:-}"; shift 2 ;;
    --category)
      CATEGORY="${2:-2}"; shift 2 ;;
    --policy)
      POLICY="${2:-}"; shift 2 ;;
    *)
      EXTRA_INSTALL_ARGS+=("$1")
      shift ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SCAN="$ROOT_DIR/scripts/scan_hub_slug.py"

if [[ ! -f "$SCAN" ]]; then
  echo "ERROR: scan_hub_slug.py not found at $SCAN"
  exit 1
fi

if [[ -z "$POLICY" ]]; then
  POLICY="$ROOT_DIR/references/audit-policy.gc.json"
fi

STAMP="$(date -u +%Y%m%d-%H%M%S)"
LOG_DIR="${HOME}/.openclaw/workspace/.learnings"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/skill-audit-${SLUG}-${STAMP}.log"

echo "[skill-check] auditing '$SLUG' (category=$CATEGORY)..."
set +e
if [[ -n "$VERSION" ]]; then
  timeout 180 python3 "$SCAN" "$SLUG" --version "$VERSION" --category "$CATEGORY" --policy "$POLICY" >"$REPORT" 2>&1
  RC=$?
else
  timeout 180 python3 "$SCAN" "$SLUG" --category "$CATEGORY" --policy "$POLICY" >"$REPORT" 2>&1
  RC=$?
fi
set -e

if [[ $RC -ne 0 ]]; then
  echo "[skill-check] audit execution failed (exit=$RC). install blocked."
  echo "Report: $REPORT"
  exit 1
fi

if ! grep -q '"verdict": "APPROVED"' "$REPORT"; then
  echo "[skill-check] verdict is not APPROVED. install blocked."
  echo "Report: $REPORT"
  grep -n '"verdict"\|"riskScore"\|"next_actions"' "$REPORT" || true
  exit 1
fi

echo "[skill-check] APPROVED ✅ installing '$SLUG'..."
if [[ -n "$VERSION" ]]; then
  clawhub install "$SLUG" --version "$VERSION" --force "${EXTRA_INSTALL_ARGS[@]}"
else
  clawhub install "$SLUG" --force "${EXTRA_INSTALL_ARGS[@]}"
fi

echo "[skill-check] done. audit report: $REPORT"
