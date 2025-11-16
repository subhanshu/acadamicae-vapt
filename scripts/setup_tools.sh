#!/bin/bash
# Setup script for VAPT testing tools

set -e

echo "Setting up VAPT testing environment..."

# Update package lists
sudo apt-get update -qq

# Install basic tools
echo "Installing basic tools..."
sudo apt-get install -y -qq \
    git \
    curl \
    wget \
    python3 \
    python3-pip \
    nodejs \
    npm \
    jq \
    nmap \
    nikto \
    sqlmap \
    > /dev/null 2>&1

# Install Python security tools
echo "Installing Python security tools..."
pip3 install --quiet --upgrade pip
pip3 install --quiet \
    semgrep \
    bandit \
    pip-audit \
    safety \
    trufflehog \
    detect-secrets \
    nuclei \
    > /dev/null 2>&1

# Install Node.js security tools
echo "Installing Node.js security tools..."
npm install -g --quiet \
    eslint \
    eslint-plugin-security \
    npm-audit-resolver \
    > /dev/null 2>&1

# Install OWASP ZAP (if not available, we'll use alternative methods)
echo "Checking for OWASP ZAP..."
if ! command -v zap-cli &> /dev/null; then
    echo "ZAP CLI not found, will use alternative methods"
fi

# Install additional tools
echo "Installing additional tools..."
pip3 install --quiet \
    requests \
    beautifulsoup4 \
    lxml \
    > /dev/null 2>&1

echo "Tool setup complete!"
