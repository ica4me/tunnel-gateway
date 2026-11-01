#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -d "$ROOT_DIR/playbooks" ]]; then ROOT_DIR="$(dirname "$ROOT_DIR")"; fi
cd "$ROOT_DIR"

usage() {
  printf 'Usage: %s INVENTORY [ansible-playbook options...]\n' "$0" >&2
  printf '       %s --local [ansible-playbook options...]\n' "$0" >&2
}

check_supported_local_os() {
  . /etc/os-release
  case "${ID:-}:${VERSION_ID:-}" in
    debian:12|debian:13|ubuntu:20.04|ubuntu:22.04|ubuntu:24.04) ;;
    *)
      printf 'OS local bootstrap tidak didukung: %s %s\n' "${ID:-unknown}" "${VERSION_ID:-unknown}" >&2
      exit 2
      ;;
  esac
}

collect_local_prompts() {
  local domain="${TUNNEL_DOMAIN:-}" email="${ADMIN_EMAIL:-}" cert_mode="${CERT_MODE:-selfsigned}"
  [[ -n "$domain" ]] || read -r -p 'Domain tunnel (contoh: gw.example.com): ' domain
  [[ -n "$email" ]] || read -r -p 'Email admin ACME: ' email
  case "$cert_mode" in
    dns_cloudflare|http01|selfsigned) ;;
    *)
      printf 'CERT_MODE tidak valid: %s\n' "$cert_mode" >&2
      exit 2
      ;;
  esac
  [[ -n "$domain" && -n "$email" ]] || { printf 'Domain dan email wajib diisi.\n' >&2; exit 2; }
  BOOTSTRAP_EXTRA_VARS=(
    "tunnel_domain=$domain"
    "admin_email=$email"
    "cert_mode=$cert_mode"
  )
}

if [[ "${1:-}" == "--local" ]]; then
  shift
  check_supported_local_os
  collect_local_prompts
  INV='localhost,'
  CONN_ARGS=(-c local -e "${BOOTSTRAP_EXTRA_VARS[0]}" -e "${BOOTSTRAP_EXTRA_VARS[1]}" -e "${BOOTSTRAP_EXTRA_VARS[2]}")
elif [[ $# -ge 1 && -f "$1" ]]; then
  INV="$1"
  shift
  CONN_ARGS=()
else
  usage
  exit 2
fi

PYTHON="${BOOTSTRAP_PYTHON:-python3}"
"$PYTHON" -c 'import sys; assert (3,10) <= sys.version_info[:2] <= (3,12), "Controller Python harus 3.10-3.12; set BOOTSTRAP_PYTHON"'
if [[ -x .venv/bin/python ]]; then
  .venv/bin/python -c 'import sys; assert (3,10) <= sys.version_info[:2] <= (3,12), "Existing .venv tidak kompatibel; simpan lalu gunakan venv baru"'
fi
"$PYTHON" -m venv .venv
.venv/bin/python -m pip install -r release/requirements.txt
.venv/bin/ansible-galaxy collection install -r requirements.yml
for playbook in prepare-server site commit-server; do
  .venv/bin/ansible-playbook -i "$INV" "playbooks/$playbook.yml" "${CONN_ARGS[@]}" "$@"
done
