#!/usr/bin/env bash
# install-ca.sh — Install the web-sieve root CA into the OS trust store and NSS
# databases used by Firefox and Chromium.
#
# Usage:
#   ./scripts/install-ca.sh [--ca-cert PATH]
#
# Options:
#   --ca-cert PATH   Path to the root CA PEM file.
#                    Defaults to ~/.config/web-sieve/ca.crt

set -euo pipefail

# --- Defaults ---
DEFAULT_CA_CERT="${XDG_CONFIG_HOME:-$HOME/.config}/web-sieve/ca.crt"
CA_CERT=""

# --- Argument parsing ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ca-cert)
            CA_CERT="$2"
            shift 2
            ;;
        --ca-cert=*)
            CA_CERT="${1#*=}"
            shift
            ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

CA_CERT="${CA_CERT:-$DEFAULT_CA_CERT}"

if [[ ! -f "$CA_CERT" ]]; then
    echo "Error: CA certificate not found at '$CA_CERT'" >&2
    echo "Run 'web-sieve' at least once to generate the CA, or pass --ca-cert PATH." >&2
    exit 1
fi

echo "Installing CA certificate: $CA_CERT"

# --- OS trust store ---
install_system_trust() {
    if command -v update-ca-certificates &>/dev/null; then
        # Debian / Ubuntu
        local dest="/usr/local/share/ca-certificates/web-sieve.crt"
        echo "→ Installing to $dest (Debian/Ubuntu)"
        cp "$CA_CERT" "$dest"
        update-ca-certificates
    elif command -v update-ca-trust &>/dev/null; then
        # Red Hat / Fedora / CentOS
        local dest="/etc/pki/ca-trust/source/anchors/web-sieve.crt"
        echo "→ Installing to $dest (Red Hat/Fedora)"
        cp "$CA_CERT" "$dest"
        update-ca-trust extract
    else
        echo "⚠ Could not detect OS trust store tool." >&2
        echo "  Manually copy '$CA_CERT' to your system CA bundle." >&2
    fi
}

# --- NSS databases ---
install_nss() {
    if ! command -v certutil &>/dev/null; then
        echo ""
        echo "⚠ certutil not found — skipping NSS installation."
        echo "  To install the CA in Firefox/Chromium manually:"
        echo "    1. Open Firefox → Settings → Privacy & Security → View Certificates"
        echo "    2. Import '$CA_CERT' and check 'Trust this CA to identify websites'"
        echo "  To install certutil (Debian/Ubuntu): sudo apt install libnss3-tools"
        echo "  To install certutil (Red Hat/Fedora): sudo dnf install nss-tools"
        return
    fi

    local cert_name="web-sieve Root CA"
    local nss_dbs=()

    # Firefox profiles
    shopt -s nullglob
    for profile in \
        "$HOME/.mozilla/firefox/"*.default* \
        "$HOME/.mozilla/firefox/"*.default-release* \
        "$HOME/.mozilla/firefox/"*.default-esr*
    do
        [[ -d "$profile" ]] && nss_dbs+=("$profile")
    done
    shopt -u nullglob

    # Chromium / Chrome NSS database
    for chromium_nssdb in \
        "$HOME/.pki/nssdb" \
        "$HOME/.config/chromium/Default" \
        "$HOME/.config/google-chrome/Default"
    do
        [[ -d "$chromium_nssdb" ]] && nss_dbs+=("$chromium_nssdb")
    done

    if [[ ${#nss_dbs[@]} -eq 0 ]]; then
        echo "⚠ No NSS databases found (Firefox/Chromium not installed or not yet run)."
        return
    fi

    for db in "${nss_dbs[@]}"; do
        echo "→ Installing into NSS database: $db"
        # Remove any old entry first to allow re-running this script.
        certutil -D -d "sql:$db" -n "$cert_name" 2>/dev/null || true
        certutil -A -d "sql:$db" -t "CT,," -n "$cert_name" -i "$CA_CERT"
    done
}

# Run as root if needed for system trust, but NSS is always per-user.
if [[ $EUID -eq 0 ]]; then
    install_system_trust
else
    echo "ℹ Not running as root — skipping system trust store."
    echo "  Re-run with sudo to install system-wide, or add '$CA_CERT' manually."
fi

install_nss

echo ""
echo "Done. You may need to restart your browser for changes to take effect."
