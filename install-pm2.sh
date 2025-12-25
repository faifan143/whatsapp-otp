#!/bin/bash

set -e

echo "=========================================="
echo "WhatsApp OTP - PM2 Installation Script"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

echo -e "${YELLOW}Step 1: Updating system packages...${NC}"
apt-get update -qq

echo -e "${YELLOW}Step 2: Installing required system dependencies...${NC}"
# Try installing with Ubuntu 24.04+ compatible packages first, fallback to standard names
apt-get install -y \
    chromium-browser \
    ca-certificates \
    libnss3 \
    libnspr4 \
    libatk1.0-0t64 \
    libatk-bridge2.0-0t64 \
    libcups2t64 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libgbm1 \
    libgtk-3-0t64 \
    libasound2t64 \
    fonts-liberation \
    libappindicator3-1 \
    xdg-utils \
    --no-install-recommends 2>/dev/null || {
    echo -e "${YELLOW}Some t64 packages not found, trying standard package names...${NC}"
    apt-get install -y \
        chromium-browser \
        ca-certificates \
        libnss3 \
        libnspr4 \
        libatk1.0-0 \
        libatk-bridge2.0-0 \
        libcups2 \
        libxkbcommon0 \
        libxcomposite1 \
        libxdamage1 \
        libxrandr2 \
        libgbm1 \
        libgtk-3-0 \
        libasound2t64 \
        fonts-liberation \
        libappindicator3-1 \
        xdg-utils \
        --no-install-recommends
}

echo -e "${YELLOW}Step 3: Checking Node.js version...${NC}"
NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
echo "Current Node.js version: $(node -v)"

if [ "$NODE_VERSION" -lt 20 ]; then
    echo -e "${YELLOW}Node.js version is less than 20. Installing Node.js 20 LTS...${NC}"
    
    # Install Node.js 20 LTS using NodeSource
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
    
    echo -e "${GREEN}Node.js updated to: $(node -v)${NC}"
elif [ "$NODE_VERSION" -ge 24 ]; then
    echo -e "${GREEN}Node.js version is compatible (v24.x detected)${NC}"
else
    echo -e "${GREEN}Node.js version is compatible (>= 20)${NC}"
fi

echo -e "${YELLOW}Step 4: Checking npm version...${NC}"
NPM_VERSION=$(npm -v | cut -d'.' -f1)
echo "Current npm version: $(npm -v)"

if [ "$NPM_VERSION" -lt 10 ]; then
    echo -e "${YELLOW}Updating npm to latest version...${NC}"
    npm install -g npm@latest
    echo -e "${GREEN}npm updated to: $(npm -v)${NC}"
else
    echo -e "${GREEN}npm version is compatible (>= 10)${NC}"
fi

echo -e "${YELLOW}Step 5: Checking PM2 installation...${NC}"
if command -v pm2 &> /dev/null; then
    PM2_VERSION=$(pm2 -v 2>/dev/null | head -1)
    echo -e "${GREEN}PM2 is already installed: $PM2_VERSION${NC}"
    echo -e "${YELLOW}To update PM2, run: npm install -g pm2@latest${NC}"
else
    echo -e "${YELLOW}Installing PM2 globally...${NC}"
    npm install -g pm2@latest
    echo -e "${GREEN}PM2 version: $(pm2 -v)${NC}"
fi

echo -e "${YELLOW}Step 6: Cleaning git repository and pulling latest changes...${NC}"
cd "$(dirname "$0")"

# Check if this is a git repository
if [ -d .git ]; then
    echo -e "${YELLOW}Discarding all local changes to tracked files...${NC}"
    git reset --hard HEAD || echo -e "${YELLOW}Warning: git reset failed (may not be a git repo)${NC}"
    
    echo -e "${YELLOW}Removing untracked files and directories...${NC}"
    git clean -fd || echo -e "${YELLOW}Warning: git clean failed${NC}"
    
    echo -e "${YELLOW}Pulling latest changes from repository...${NC}"
    git pull || echo -e "${YELLOW}Warning: git pull failed (may not have remote configured)${NC}"
    
    echo -e "${GREEN}Repository cleaned and updated${NC}"
else
    echo -e "${YELLOW}Not a git repository, skipping git cleanup${NC}"
fi

echo -e "${YELLOW}Step 7: Installing project dependencies...${NC}"
npm install --production

echo -e "${YELLOW}Step 8: Creating logs directory...${NC}"
mkdir -p logs

echo -e "${YELLOW}Step 9: Setting up PM2 startup script...${NC}"
pm2 startup systemd -u root --hp /root
echo -e "${GREEN}PM2 startup configured${NC}"

echo ""
echo -e "${GREEN}=========================================="
echo "Installation Complete!"
echo "==========================================${NC}"
echo ""
echo "Next steps:"
echo "1. Start the application: pm2 start ecosystem.config.js"
echo "2. Save PM2 process list: pm2 save"
echo "3. Check status: pm2 status"
echo "4. View logs: pm2 logs whatsapp-otp"
echo "5. Monitor: pm2 monit"
echo ""
echo "To stop Docker container (if running):"
echo "  docker-compose down"
echo ""

