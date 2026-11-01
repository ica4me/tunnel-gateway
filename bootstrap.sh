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
    debian:12|debian:13|ubuntu:22.04|ubuntu:24.04|ubuntu:26.04) ;;
    *)
      printf 'OS local bootstrap tidak didukung: %s %s\n' "${ID:-unknown}" "${VERSION_ID:-unknown}" >&2
      exit 2
      ;;
  esac
}

collect_local_prompts() {
  local domain="${TUNNEL_DOMAIN:-}" email="${ADMIN_EMAIL:-}" cert_mode="${CERT_MODE:-http01}"
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

# Ansible A2 controller bootstrap
ANSIBLE_VENV=".venv-a2"
UV_VENV=".venv-bootstrap"

# Install pinned uv into an isolated environment if missing
if [[ ! -x "$UV_VENV/bin/uv" ]]; then
  python3 -m venv "$UV_VENV"
  "$UV_VENV/bin/python" -m pip install 'uv==0.13.6'
fi

UV_BIN="$UV_VENV/bin/uv"

# Prefer system Python when supported by Ansible 2.21
if [[ -n "${BOOTSTRAP_PYTHON:-}" ]]; then
  CONTROLLER_PYTHON="$BOOTSTRAP_PYTHON"
elif python3 -c \
  'import sys; assert (3,12) <= sys.version_info[:2] <= (3,14)' \
  2>/dev/null; then
  CONTROLLER_PYTHON="$(command -v python3)"
else
  "$UV_BIN" python install 3.12
  CONTROLLER_PYTHON="$("$UV_BIN" python find 3.12)"
fi

# Validate selected interpreter
"$CONTROLLER_PYTHON" -c \
  'import sys; assert (3,12) <= sys.version_info[:2] <= (3,14)'

# Create A2 environment without replacing an existing one
if [[ ! -x "$ANSIBLE_VENV/bin/python" ]]; then
  "$UV_BIN" venv \
    --python "$CONTROLLER_PYTHON" \
    "$ANSIBLE_VENV"
fi

"$ANSIBLE_VENV/bin/python" -c \
  'import sys; assert (3,12) <= sys.version_info[:2] <= (3,14)'

# Install pinned Ansible
"$UV_BIN" pip install \
  --python "$ANSIBLE_VENV/bin/python" \
  -r release/requirements.txt

"$ANSIBLE_VENV/bin/ansible-galaxy" collection install \
  -r requirements.yml

# Deployment remains disabled until package preparation is ready
if [[ "${BOOTSTRAP_DEPLOY_APPROVED:-false}" != "true" ]]; then
  echo "A2 bootstrap prepared. Deployment not started."
  exit 0
fi

# Require separate authorization for package installation
if [[ "${BOOTSTRAP_PACKAGES_APPROVED:-false}" != "true" ]]; then
  echo "Package installation not approved. Deployment stopped." >&2
  exit 2
fi

# Phase 1: Install packages before configuring services
"$ANSIBLE_VENV/bin/ansible-playbook" \
  -i "$INV" \
  playbooks/prepare-packages.yml \
  "${CONN_ARGS[@]}" \
  -e package_install_approved=true \
  "$@"

# Phase 2: Configure and verify services
for playbook in prepare-server site commit-server; do
  "$ANSIBLE_VENV/bin/ansible-playbook" \
    -i "$INV" \
    "playbooks/$playbook.yml" \
    "${CONN_ARGS[@]}" "$@"
done
