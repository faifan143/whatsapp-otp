FROM node:18-bullseye

ENV NODE_ENV=production

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .
RUN mkdir -p .wwebjs_auth

EXPOSE 3002
CMD ["node", "server.js"]
