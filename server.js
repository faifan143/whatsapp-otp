const express = require("express");
const { Client, LocalAuth } = require("whatsapp-web.js");
const qrcode = require("qrcode-terminal");
const fs = require("fs");

const app = express();
const port = process.env.PORT || 3002;

app.use(express.json());

const AUTH_DIR = "./.wwebjs_auth";
if (!fs.existsSync(AUTH_DIR)) fs.mkdirSync(AUTH_DIR, { recursive: true });

let isAuthenticated = false;
let isClientReady = false;

const client = new Client({
  authStrategy: new LocalAuth({ clientId: "default", dataPath: AUTH_DIR }),
  puppeteer: {
    headless: true,
    args: [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
      "--mute-audio",
    ],
  },
});

client.on("qr", (qr) => {
  console.log("[QR] Scan this QR code to authenticate:");
  qrcode.generate(qr, { small: true });
  isAuthenticated = false;
  isClientReady = false;
});

client.on("authenticated", () => {
  console.log("[AUTH] WhatsApp authenticated!");
  isAuthenticated = true;
});

client.on("ready", () => {
  console.log("[READY] WhatsApp client is ready to send messages!");
  isClientReady = true;
});

client.on("disconnected", async (reason) => {
  console.log("[DISCONNECT] Reason:", reason);
  isAuthenticated = false;
  isClientReady = false;
});

function formatPhone(phone) {
  let num = phone.toString().replace(/[^0-9]/g, "");
  if (num.startsWith("0")) num = "963" + num.slice(1);
  return num + "@c.us";
}

async function sendMessageWithRetry(chatId, text, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await client.sendMessage(chatId, text);
    } catch (err) {
      console.log(`[SEND] Attempt ${i + 1} failed: ${err.message}`);
      if (i < maxRetries - 1) {
        await new Promise(r => setTimeout(r, 2000));
      } else {
        throw err;
      }
    }
  }
}

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    authenticated: isAuthenticated,
    ready: isClientReady,
  });
});

app.get("/status", (req, res) => {
  res.json({
    authenticated: isAuthenticated,
    ready: isClientReady,
    timestamp: new Date().toISOString(),
  });
});

app.post("/send-otp", async (req, res) => {
  const { phoneNumber, otp, purpose } = req.body;

  if (!phoneNumber || !otp) {
    return res.status(400).json({
      success: false,
      message: "Phone number and OTP required",
    });
  }

  if (!isClientReady) {
    return res.status(503).json({
      success: false,
      message: "WhatsApp not ready. Scan QR code in server logs.",
    });
  }

  try {
    const chatId = formatPhone(phoneNumber);
    const msg = `رمز التحقق: ${otp}`;
    await sendMessageWithRetry(chatId, msg);
    res.json({ success: true, message: "OTP sent" });
  } catch (err) {
    console.error("[SEND-OTP ERROR]", err.message);
    res.status(500).json({
      success: false,
      message: "Failed to send OTP: " + err.message,
    });
  }
});

app.post("/send-message", async (req, res) => {
  const { phoneNumber, message } = req.body;

  if (!phoneNumber || !message) {
    return res.status(400).json({
      success: false,
      message: "Phone number and message required",
    });
  }

  if (!isClientReady) {
    return res.status(503).json({
      success: false,
      message: "WhatsApp not ready. Scan QR code in server logs.",
    });
  }

  try {
    const chatId = formatPhone(phoneNumber);
    await sendMessageWithRetry(chatId, message);
    res.json({ success: true, message: "Message sent" });
  } catch (err) {
    console.error("[SEND-MESSAGE ERROR]", err.message);
    res.status(500).json({
      success: false,
      message: "Failed to send message: " + err.message,
    });
  }
});

client.initialize();

app.listen(port, "0.0.0.0", () => {
  console.log(`[SERVER] Running on http://0.0.0.0:${port}`);
});

process.on("SIGINT", async () => {
  console.log("[SHUTDOWN] Closing...");
  await client.destroy();
  process.exit(0);
});