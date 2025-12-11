FROM node:18-bullseye

# Install Chromium + runtime deps commonly needed by headless Chromium
RUN apt-get update && apt-get install -y \
    chromium \
    ca-certificates \
    fonts-liberation \
    fonts-ipafont-gothic fonts-wqy-zenhei fonts-thai-tlwg fonts-kacst fonts-freefont-ttf \
    libnss3 libnspr4 \
    libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 \
    libxkbcommon0 \
    libxcomposite1 libxdamage1 libxrandr2 \
    libgbm1 \
    libgtk-3-0 \
    libasound2 \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Instruct any puppeteer usage to NOT download Chromium
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium
ENV NODE_ENV=production

WORKDIR /usr/src/app

# Install dependencies
COPY package*.json ./
RUN npm ci --omit=dev

# Copy app code
COPY . .

# Ensure auth directory exists (actual persistence is via volume mount)
RUN mkdir -p .wwebjs_auth

EXPOSE 3002
CMD ["node", "server.js"]
