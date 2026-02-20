#!/usr/bin/env bash
set-euo pipefail

# Rebuild + restart WinNativeSSH on a remote Windows host.
#
# Why:
# - Building on Windows fails with "os error 5" if WinNativeSSH is running (it holds vlt-sshd.exe open).
# - We MUST NOT stop OpenSSH(22) if we rely on it for access; only stop WinNativeSSH.
#
# Usage:
#   ./scripts/remote_rebuild_winnativessh.sh user@host [remote_repo_root]
#
# Notes:
# - Requires key-based SSH to port 22 working.
# - Uses StrictHostKeyChecking=no with a temp known_hosts file to avoid dev host-key churn.

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 user@host [remote_repo_root]"
  exit 2
fi

TARGET="$1"
REMOTE_REPO_ROOT="${2:-}"
KNOWN="/tmp/ssh_known_hosts_winnativessh_${TARGET//[^a-zA-Z0-9_.-]/_}"

ssh_cmd() {
  ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile="$KNOWN" "$TARGET" "$@"
}

repo_cd_ps() {
  if [[ -n "$REMOTE_REPO_ROOT" ]]; then
    if [[ "$REMOTE_REPO_ROOT" == *"'"* ]]; then
      echo "Write-Error \"remote_repo_root must not contain single quotes\"; exit 2"
    else
      echo "Set-Location '$REMOTE_REPO_ROOT'"
    fi
  else
    # Default: %USERPROFILE%\\ssh-server-deploy
    echo "Set-Location (Join-Path \\$env:USERPROFILE 'ssh-server-deploy')"
  fi
}

echo "[1/5] Stop WinNativeSSH (only)"
ssh_cmd "powershell -NoProfile -NonInteractive -Command \"Stop-Service WinNativeSSH -Force; Start-Sleep -Seconds 1; Get-Service WinNativeSSH | Select-Object Name,Status,StartType | Format-Table -AutoSize\""

echo "[2/5] Build release"
ssh_cmd "powershell -NoProfile -NonInteractive -Command \"$(repo_cd_ps); cargo build --release\""

echo "[3/5] Start WinNativeSSH"
ssh_cmd "powershell -NoProfile -NonInteractive -Command \"Start-Service WinNativeSSH; Start-Sleep -Seconds 1; Get-Service WinNativeSSH | Select-Object Name,Status,StartType | Format-Table -AutoSize\""

echo "[4/5] Smoke tests (2222)"
ssh -o BatchMode=yes -o ConnectTimeout=10 -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile="/tmp/ssh_known_hosts_winnativessh_${TARGET//[^a-zA-Z0-9_.-]/_}_2222" "$TARGET" "echo OK" || true
ssh -o BatchMode=yes -o ConnectTimeout=10 -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile="/tmp/ssh_known_hosts_winnativessh_${TARGET//[^a-zA-Z0-9_.-]/_}_2222" "$TARGET" "sysinfo" || true
ssh -o BatchMode=yes -o ConnectTimeout=10 -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile="/tmp/ssh_known_hosts_winnativessh_${TARGET//[^a-zA-Z0-9_.-]/_}_2222" "$TARGET" "powershell -NoProfile -NonInteractive -Command \"1+1\"" || true
ssh -o BatchMode=yes -o ConnectTimeout=10 -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile="/tmp/ssh_known_hosts_winnativessh_${TARGET//[^a-zA-Z0-9_.-]/_}_2222" "$TARGET" "where.exe cmd" || true
ssh -o BatchMode=yes -o ConnectTimeout=10 -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile="/tmp/ssh_known_hosts_winnativessh_${TARGET//[^a-zA-Z0-9_.-]/_}_2222" "$TARGET" "tasklist" || true
ssh -o BatchMode=yes -o ConnectTimeout=10 -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile="/tmp/ssh_known_hosts_winnativessh_${TARGET//[^a-zA-Z0-9_.-]/_}_2222" "$TARGET" "tasklist /FI \"IMAGENAME eq explorer.exe\"" || true
ssh -o BatchMode=yes -o ConnectTimeout=10 -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile="/tmp/ssh_known_hosts_winnativessh_${TARGET//[^a-zA-Z0-9_.-]/_}_2222" "$TARGET" "netinfo" || true
ssh -o BatchMode=yes -o ConnectTimeout=10 -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile="/tmp/ssh_known_hosts_winnativessh_${TARGET//[^a-zA-Z0-9_.-]/_}_2222" "$TARGET" "wsl-status" || true
ssh -o BatchMode=yes -o ConnectTimeout=10 -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile="/tmp/ssh_known_hosts_winnativessh_${TARGET//[^a-zA-Z0-9_.-]/_}_2222" "$TARGET" "wsl.exe --status" || true

echo "[5/5] Done"
