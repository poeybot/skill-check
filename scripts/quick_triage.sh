#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-}"
if [[ -z "$TARGET" || ! -d "$TARGET" ]]; then
  echo "Usage: quick_triage.sh /path/to/skill"
  exit 2
fi

echo "== Quick triage: $TARGET =="

echo "[1] Metadata files"
ls "$TARGET" | rg -n "SKILL\.md|README|LICENSE|package\.json|pyproject|requirements|setup\.py" || true

echo "[2] Suspicious install/download-exec patterns"
rg -n -S "curl\s+.*\|\s*(sh|bash)|wget\s+.*\|\s*(sh|bash)|Invoke-WebRequest|subprocess\.|os\.system\(|child_process|eval\(|exec\(" "$TARGET" || true

echo "[3] Capability hints"
rg -n -S "requests\.|httpx\.|fetch\(|axios|socket|websocket|cron|systemd|launchd|schtasks|sudo|\.ssh|\.aws|keychain|/etc|\.env" "$TARGET" || true

echo "[4] Archive extraction risk patterns"
rg -n -S "extractall\(|tarfile\.extract\(|zipfile\.ZipFile" "$TARGET" || true

echo "[5] Obfuscation hints"
rg -n -S "base64\.b64decode|zlib\.decompress|marshal\.loads|eval\(|exec\(|fromhex\(" "$TARGET" || true

echo "== Triage done =="
echo "If anything above is unexpected for declared scope => CAUTION or REJECT."
