#!/usr/bin/env bash
# Tunnel Gateway installer - same command on Debian 12/13 and Ubuntu 22.04/24.04/26.04.
#   bash bootstrap.sh [INVENTORY] [--setup-only] [ansible-playbook options...]
# Steps: controller Python (uv when the OS Python is < 3.12) -> .venv + pinned ansible-core
#        -> prepare-packages -> prepare-speedtest (optional) -> prepare-server -> site -> commit-server
# Env:   PACKAGE_MODE=pinned|latest-compatible   SPEEDTEST=0 to skip Speedtest
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -d "$ROOT_DIR/playbooks" ]]; then ROOT_DIR="$(dirname "$ROOT_DIR")"; fi
cd "$ROOT_DIR"

say() { printf '%s\n' "$*"; }
die() { printf 'GAGAL: %s\n' "$*" >&2; exit 1; }

INV="inventories/new-server/hosts.yml"
SETUP_ONLY=0
if [[ $# -ge 1 && "$1" != -* ]]; then INV="$1"; shift; fi
if [[ "${1:-}" == "--setup-only" ]]; then SETUP_ONLY=1; shift; fi
[[ -f "$INV" ]] || die "inventory tidak ditemukan: $INV"

LOCAL=0
grep -Eq '^[[:space:]]*ansible_connection:[[:space:]]*local' "$INV" && LOCAL=1
if [[ $LOCAL == 1 ]]; then
  [[ $EUID -eq 0 ]] || die "mode lokal harus dijalankan sebagai root."
  . /etc/os-release
  case "${ID:-}:${VERSION_ID:-}" in
    debian:12|debian:13|ubuntu:22.04|ubuntu:24.04|ubuntu:26.04) ;;
    *) die "OS tidak didukung: ${PRETTY_NAME:-unknown}. Didukung: Debian 12/13, Ubuntu 22.04/24.04/26.04." ;;
  esac
fi

# 1. Python venv support (fresh cloud images often lack python3-venv).
if ! python3 -c 'import ensurepip, venv' >/dev/null 2>&1; then
  if [[ $EUID -eq 0 ]] && command -v apt-get >/dev/null; then
    say ">>> Memasang python3-venv"
    apt-get update -q >/dev/null || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q python3-venv python3-pip >/dev/null
  else
    die "python3-venv belum terpasang. Jalankan: sudo apt-get install -y python3-venv python3-pip"
  fi
fi

# 2. uv (pinned) provides Python 3.12 when the OS Python is older (Ubuntu 22.04 = 3.10, Debian 12 = 3.11).
UV_VENV=".venv-bootstrap"
if [[ ! -x "$UV_VENV/bin/uv" ]]; then
  say ">>> Menyiapkan uv"
  python3 -m venv "$UV_VENV"
  "$UV_VENV/bin/python" -m pip install -q 'uv==0.13.6'
fi
UV="$UV_VENV/bin/uv"
supported='import sys; sys.exit(0 if (3,12) <= sys.version_info[:2] <= (3,14) else 1)'
if python3 -c "$supported" 2>/dev/null; then
  CONTROLLER_PYTHON="$(command -v python3)"
else
  say ">>> Python sistem $(python3 -V 2>&1 | cut -d' ' -f2) < 3.12: memasang Python 3.12 terpisah untuk Ansible"
  "$UV" python install 3.12 >/dev/null
  CONTROLLER_PYTHON="$("$UV" python find --python-preference only-managed --no-project 3.12)"
fi

# 3. One Ansible venv (.venv). An older .venv on Python < 3.12 is kept aside, not deleted.
if [[ -x .venv/bin/python ]] && ! .venv/bin/python -c "$supported" 2>/dev/null; then
  old=".venv.old-$(date +%Y%m%d-%H%M%S)"
  mv .venv "$old"
  say ">>> .venv lama (Python < 3.12) dipindahkan ke $old"
fi
[[ -x .venv/bin/python ]] || "$UV" venv --python "$CONTROLLER_PYTHON" .venv >/dev/null
"$UV" pip install -q --python .venv/bin/python -r release/requirements.txt
.venv/bin/ansible-galaxy collection install -r requirements.yml >/dev/null
say ">>> ansible-core $(.venv/bin/python -c 'import ansible.release as r; print(r.__version__)') (Python $(.venv/bin/python -V | cut -d' ' -f2))"

if [[ $SETUP_ONLY == 1 ]]; then
  say "Setup selesai (--setup-only). Deploy: bash bootstrap.sh $INV"
  exit 0
fi

# 4. Package version mode.
MODE="${PACKAGE_MODE:-}"
if [[ -z "$MODE" ]]; then
  if [[ -t 0 ]]; then
    say ""
    say "Pilih mode paket OS:"
    say "  1) pinned            - pasang dari repo OS, jangan upgrade paket yang sudah ada [disarankan]"
    say "  2) latest-compatible - upgrade semua paket gateway ke versi terbaru repo OS"
    read -r -p "Pilihan [1]: " answer
    case "${answer:-1}" in 1) MODE=pinned ;; 2) MODE=latest-compatible ;; *) die "pilihan tidak valid" ;; esac
  else
    MODE=pinned
  fi
fi

run_pb() { .venv/bin/ansible-playbook -i "$INV" "playbooks/$1.yml" "${@:2}"; }

say ""; say "=== Tahap 1/5: paket OS ($MODE)"
run_pb prepare-packages -e "package_version_mode=$MODE" "$@"
say ""; say "=== Tahap 2/5: Speedtest Ookla (opsional)"
if [[ "${SPEEDTEST:-1}" != "0" ]]; then
  run_pb prepare-speedtest "$@" || say "Speedtest dilewati; instalasi tetap lanjut."
else
  say "dilewati (SPEEDTEST=0)"
fi
say ""; say "=== Tahap 3/5: rollback firewall (prepare-server)"
run_pb prepare-server "$@"
say ""; say "=== Tahap 4/5: konfigurasi service (site)"
run_pb site "$@"
say ""; say "=== Tahap 5/5: verifikasi & commit"
run_pb commit-server "$@"
say ""
say "SELESAI. Buka menu: sudo menu"
say "Domain belum diisi? Server memakai IP + sertifikat selfsigned; atur di Menu Sistem > 4."
