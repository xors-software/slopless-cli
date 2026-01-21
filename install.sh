#!/bin/bash
# Slopless CLI installer
# Usage: curl -fsSL https://unslop.dev/install.sh | bash

set -e

REPO="xors-software/slopless-cli"
INSTALL_DIR="$HOME/.local/bin"

echo "🛡️  Installing Slopless CLI..."
echo ""

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    echo "   Install Python from https://python.org or via your package manager."
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 11 ]); then
    echo "❌ Python 3.11+ is required (you have $PYTHON_VERSION)"
    exit 1
fi

echo "✓ Python $PYTHON_VERSION detected"

# Install via pipx if available, otherwise pip
if command -v pipx &> /dev/null; then
    echo "✓ Installing with pipx..."
    pipx install slopless --force 2>/dev/null || pipx install git+https://github.com/$REPO.git --force
else
    echo "ℹ️  pipx not found, using pip..."
    
    # Try pip install
    if pip3 install --user slopless 2>/dev/null; then
        echo "✓ Installed via pip"
    else
        echo "  Installing from GitHub..."
        pip3 install --user git+https://github.com/$REPO.git
    fi
fi

# Check if slopless is in PATH
if command -v slopless &> /dev/null; then
    echo ""
    echo "✅ Slopless installed successfully!"
    echo ""
    slopless --version
else
    # Add to PATH hint
    echo ""
    echo "✅ Slopless installed!"
    echo ""
    echo "⚠️  Add this to your shell profile (~/.bashrc or ~/.zshrc):"
    echo '   export PATH="$HOME/.local/bin:$PATH"'
    echo ""
    echo "   Then restart your terminal or run: source ~/.zshrc"
fi

echo ""
echo "🚀 Get started:"
echo "   slopless login        # Authenticate with your license key"
echo "   slopless scan .       # Scan current directory"
echo ""
echo "📄 Get a license at https://unslop.dev/pricing"
