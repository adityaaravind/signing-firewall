#!/usr/bin/env bash
# Signing Firewall - one-command installer (Linux / macOS)
# Usage: curl -fsSL https://raw.githubusercontent.com/adityaaravind/signing-firewall/main/install.sh | bash
set -e
REPO="adityaaravind/signing-firewall"
INSTALL_DIR="${HOME}/.local/bin"
mkdir -p "$INSTALL_DIR"
if [ -f "signing-firewall.py" ]; then
  echo "Installing local signing-firewall.py ..."
  cp signing-firewall.py "$INSTALL_DIR/signing-firewall"
else
  echo "Downloading signing-firewall.py from GitHub ..."
  curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/signing-firewall.py" -o "$INSTALL_DIR/signing-firewall"
fi
chmod +x "$INSTALL_DIR/signing-firewall"
echo ""
echo "Installed to $INSTALL_DIR/signing-firewall"
echo "Make sure $INSTALL_DIR is on your PATH, then run:"
echo "  signing-firewall serve"
echo "  signing-firewall dashboard"
"$INSTALL_DIR/signing-firewall" --help | head -20
