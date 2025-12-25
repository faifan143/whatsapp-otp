#!/bin/bash

echo "=========================================="
echo "System Information & Installed Programs"
echo "=========================================="
echo ""

echo "--- Operating System ---"
cat /etc/os-release 2>/dev/null || uname -a
echo ""

echo "--- Node.js & npm ---"
node --version 2>/dev/null || echo "Node.js: Not installed"
npm --version 2>/dev/null || echo "npm: Not installed"
echo ""

echo "--- PM2 ---"
pm2 --version 2>/dev/null || echo "PM2: Not installed"
echo ""

echo "--- Docker ---"
docker --version 2>/dev/null || echo "Docker: Not installed"
docker-compose --version 2>/dev/null || echo "Docker Compose: Not installed"
echo ""

echo "--- Chromium/Chrome (for Puppeteer) ---"
chromium --version 2>/dev/null || chromium-browser --version 2>/dev/null || google-chrome --version 2>/dev/null || echo "Chromium/Chrome: Not installed"
echo ""

echo "--- System Package Manager (Debian/Ubuntu) ---"
if command -v apt &> /dev/null; then
    echo "apt list --installed | head -20"
    apt list --installed 2>/dev/null | head -20
    echo "... (showing first 20, use 'apt list --installed | wc -l' for total count)"
    echo "Total packages: $(apt list --installed 2>/dev/null | wc -l)"
fi

if command -v dpkg &> /dev/null; then
    echo ""
    echo "dpkg --get-selections | head -20"
    dpkg --get-selections 2>/dev/null | head -20
fi

echo ""
echo "--- System Package Manager (RedHat/CentOS) ---"
if command -v yum &> /dev/null; then
    echo "yum list installed | head -20"
    yum list installed 2>/dev/null | head -20
fi

if command -v dnf &> /dev/null; then
    echo "dnf list installed | head -20"
    dnf list installed 2>/dev/null | head -20
fi

if command -v rpm &> /dev/null; then
    echo ""
    echo "rpm -qa | head -20"
    rpm -qa 2>/dev/null | head -20
fi

echo ""
echo "--- Memory & Disk ---"
free -h
echo ""
df -h
echo ""

echo "--- Network ---"
ip addr show | grep -E "inet " | head -5
echo ""

echo "=========================================="
echo "Check complete!"
echo "=========================================="

