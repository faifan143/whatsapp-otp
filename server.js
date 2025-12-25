require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const { Client, LocalAuth } = require("whatsapp-web.js");
const qrcode = require("qrcode-terminal");
const fs = require("fs");
const path = require("path");

const app = express();
const port = process.env.PORT || 3002;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Simple session storage (in-memory)
const sessions = new Set();

// SSE clients for real-time updates
const sseClients = new Set();

// Authentication middleware
const requireAuth = (req, res, next) => {
  const sessionId = req.cookies.sessionId;
  if (sessionId && sessions.has(sessionId)) {
    return next();
  }
  res.status(401).json({ error: 'Unauthorized' });
};

// Helper function to register routes with and without /otp-service prefix
function registerRoute(method, path, ...handlers) {
  // Wrap handlers in try-catch for error handling
  const wrappedHandlers = handlers.map(handler => {
    return async (req, res, next) => {
      try {
        const result = handler(req, res, next);
        // If handler returns a promise, wait for it
        if (result && typeof result.then === 'function') {
          await result;
        }
      } catch (error) {
        console.error(`[ROUTE ERROR] ${method.toUpperCase()} ${path}:`, error);
        if (!res.headersSent) {
          res.status(500).json({ error: error.message || 'Internal server error' });
        }
      }
    };
  });
  
  app[method](path, ...wrappedHandlers);
  app[method](`/otp-service${path}`, ...wrappedHandlers);
}

// Login endpoint
registerRoute("post", "/api/login", (req, res) => {
  const { email, password } = req.body;
  const validEmail = process.env.LOGIN_EMAIL || "any.otp@gmail.com";
  const validPassword = process.env.LOGIN_PASSWORD;

  if (!validPassword) {
    return res.status(500).json({ error: "Login credentials not configured" });
  }

  if (email === validEmail && password === validPassword) {
    const sessionId = require("crypto").randomBytes(32).toString("hex");
    sessions.add(sessionId);
    res.cookie("sessionId", sessionId, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }); // 24 hours
    res.json({ success: true });
  } else {
    res.status(401).json({ error: "Invalid credentials" });
  }
});

// Check auth status
registerRoute("get", "/api/auth/check", (req, res) => {
  const sessionId = req.cookies.sessionId;
  res.json({ authenticated: sessionId && sessions.has(sessionId) });
});

// Server-Sent Events endpoint for real-time updates
registerRoute("get", "/api/events", requireAuth, (req, res) => {
  // Set headers for SSE
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no'); // Disable nginx buffering
  
  // Send initial connection message
  res.write(`data: ${JSON.stringify({ type: 'connected', message: 'Connected to event stream' })}\n\n`);
  
  // Add client to set
  sseClients.add(res);
  
  // Send current status
  const statusMessage = JSON.stringify({
    type: 'status',
    data: {
      authenticated: isAuthenticated,
      ready: isClientReady,
      hasQR: currentQR !== null,
      timestamp: new Date().toISOString()
    }
  });
  res.write(`data: ${statusMessage}\n\n`);
  
  // Remove client on disconnect
  req.on('close', () => {
    sseClients.delete(res);
    console.log('[SSE] Client disconnected, remaining clients:', sseClients.size);
  });
  
  // Keep connection alive with heartbeat
  const heartbeat = setInterval(() => {
    try {
      res.write(`: heartbeat\n\n`);
    } catch (err) {
      clearInterval(heartbeat);
      sseClients.delete(res);
    }
  }, 30000); // Every 30 seconds
  
  // Clear interval on disconnect
  req.on('close', () => {
    clearInterval(heartbeat);
  });
});

// Logout endpoint
registerRoute("post", "/api/logout", (req, res) => {
  const sessionId = req.cookies.sessionId;
  if (sessionId) {
    sessions.delete(sessionId);
  }
  res.clearCookie("sessionId");
  res.json({ success: true });
});

let currentQR = null;

const AUTH_DIR = "./.wwebjs_auth";
if (!fs.existsSync(AUTH_DIR)) fs.mkdirSync(AUTH_DIR, { recursive: true });

let isAuthenticated = false;
let isClientReady = false;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 5;

// Detect system Chromium path for Puppeteer
const getChromiumPath = () => {
  const possiblePaths = [
    "/usr/bin/chromium-browser",
    "/usr/bin/chromium",
    "/snap/bin/chromium",
  ];
  
  for (const chromiumPath of possiblePaths) {
    if (fs.existsSync(chromiumPath)) {
      return chromiumPath;
    }
  }
  return undefined; // Use bundled Chromium if not found
};

const chromiumPath = getChromiumPath();
const puppeteerConfig = {
  headless: true,
  args: [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--mute-audio",
    "--disable-blink-features=AutomationControlled",
    "--disable-features=IsolateOrigins,site-per-process",
  ],
};

// Use system Chromium if available
if (chromiumPath) {
  puppeteerConfig.executablePath = chromiumPath;
  console.log(`[PUPPETEER] Using system Chromium: ${chromiumPath}`);
}

const client = new Client({
  authStrategy: new LocalAuth({ clientId: "default", dataPath: AUTH_DIR }),
  puppeteer: puppeteerConfig,
  webVersionCache: {
    type: "remote",
    remotePath: "https://raw.githubusercontent.com/wppconnect-team/wa-version/main/html/2.2413.51-beta.html",
  },
});

client.on("qr", (qr) => {
  console.log("[QR] Scan this QR code to authenticate:");
  qrcode.generate(qr, { small: true });
  currentQR = qr; 
  isAuthenticated = false;
  isClientReady = false;
  reconnectAttempts = 0;
  
  // Notify all SSE clients that new QR code is available
  const message = JSON.stringify({ 
    type: 'qr_generated', 
    message: 'New QR code generated',
    timestamp: new Date().toISOString()
  });
  sseClients.forEach(client => {
    try {
      client.write(`data: ${message}\n\n`);
    } catch (err) {
      console.error('[SSE] Error sending to client:', err);
    }
  });
});

client.on("authenticated", () => {
  console.log("[AUTH] WhatsApp authenticated! QR code scanned successfully!");
  isAuthenticated = true;
  reconnectAttempts = 0;
  
  // Notify all SSE clients that QR was scanned
  const message = JSON.stringify({ 
    type: 'qr_scanned', 
    message: 'QR code scanned successfully!',
    timestamp: new Date().toISOString()
  });
  sseClients.forEach(client => {
    try {
      client.write(`data: ${message}\n\n`);
    } catch (err) {
      console.error('[SSE] Error sending to client:', err);
    }
  });
});

client.on("ready", () => {
  console.log("[READY] WhatsApp client is ready to send messages!");
  isClientReady = true;
  isAuthenticated = true;
  reconnectAttempts = 0;
  currentQR = null;
  
  // Notify all SSE clients that client is ready
  const message = JSON.stringify({ 
    type: 'ready', 
    message: 'WhatsApp client is ready!',
    timestamp: new Date().toISOString()
  });
  sseClients.forEach(client => {
    try {
      client.write(`data: ${message}\n\n`);
    } catch (err) {
      console.error('[SSE] Error sending to client:', err);
    }
  });
});

client.on("disconnected", async (reason) => {
  console.log("[DISCONNECT] Reason:", reason);
  isAuthenticated = false;
  isClientReady = false;
  
  // Only auto-reconnect if it's an unexpected disconnect (not manual logout)
  // Manual logout will have session deleted, so don't auto-reconnect
  if ((reason === "LOGOUT" || reason === "NAVIGATION") && fs.existsSync(path.join(AUTH_DIR, "session-default"))) {
    console.log("[RECONNECT] Attempting to reconnect...");
    if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
      reconnectAttempts++;
      setTimeout(() => {
        client.initialize().catch(err => {
          console.error("[RECONNECT ERROR]", err.message);
        });
      }, 5000 * reconnectAttempts);
    } else {
      console.error("[RECONNECT] Max reconnection attempts reached. Manual intervention required.");
    }
  }
});

client.on("auth_failure", (msg) => {
  console.error("[AUTH FAILURE]", msg);
  isAuthenticated = false;
  isClientReady = false;
});

function formatPhoneToE164(phone) {
  let num = phone.toString().trim();
  if (num.startsWith("+")) {
    num = num.substring(1);
  }
  num = num.replace(/[^0-9]/g, "");
  if (num.startsWith("0")) {
    num = "963" + num.substring(1);
  }
  if (num.length < 10) {
    num = "963" + num;
  }
  return num;
}

async function getChatId(phoneNumber) {
  try {
    const formattedNumber = formatPhoneToE164(phoneNumber);
    const numberId = await client.getNumberId(formattedNumber);
    if (numberId) {
      return numberId._serialized;
    }
    return formattedNumber + "@c.us";
  } catch (err) {
    console.error("[GET-CHAT-ID ERROR]", err.message);
    const formattedNumber = formatPhoneToE164(phoneNumber);
    return formattedNumber + "@c.us";
  }
}

async function sendMessageWithRetry(phoneNumber, text, maxRetries = 3) {
  let lastError = null;
  for (let i = 0; i < maxRetries; i++) {
    try {
      if (!isClientReady) {
        throw new Error("WhatsApp client is not ready");
      }
      const chatId = await getChatId(phoneNumber);
      console.log(`[SEND] Resolved chat ID: ${chatId} for phone: ${phoneNumber}`);
      const result = await client.sendMessage(chatId, text);
      return result;
    } catch (err) {
      lastError = err;
      console.log(`[SEND] Attempt ${i + 1} failed: ${err.message}`);
      if (err.message.includes("LID") || err.message.includes("No LID")) {
        console.log("[SEND] LID error detected, waiting before retry...");
        await new Promise(r => setTimeout(r, 3000));
      } else if (i < maxRetries - 1) {
        await new Promise(r => setTimeout(r, 2000));
      }
    }
  }
  throw lastError;
}

// API Endpoints
registerRoute("get", "/health", (req, res) => {
  res.json({
    status: "ok",
    authenticated: isAuthenticated,
    ready: isClientReady,
    reconnectAttempts: reconnectAttempts,
  });
});

// Test route to verify routing works
registerRoute("get", "/test", (req, res) => {
  res.json({ message: "Routes are working!", path: req.path, originalUrl: req.originalUrl });
});

registerRoute("get", "/status", (req, res) => {
  res.json({
    authenticated: isAuthenticated,
    ready: isClientReady,
    reconnectAttempts: reconnectAttempts,
    timestamp: new Date().toISOString(),
  });
});

registerRoute("get", "/api/qr", requireAuth, (req, res) => {
  // Prevent caching
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.set('Content-Type', 'application/json');
  
  res.status(200).json({ 
    qr: currentQR || null,
    ready: isClientReady,
    authenticated: isAuthenticated,
    timestamp: new Date().toISOString()
  });
});

registerRoute("post", "/api/disconnect", requireAuth, async (req, res) => {
  try {
    // Destroy the client first
    await client.destroy();
    
    // Clear state
    currentQR = null;
    isAuthenticated = false;
    isClientReady = false;
    reconnectAttempts = 0;
    
    // Delete the session directory to force new login
    const sessionPath = path.join(AUTH_DIR, "session-default");
    if (fs.existsSync(sessionPath)) {
      fs.rmSync(sessionPath, { recursive: true, force: true });
      console.log("[DISCONNECT] Session directory deleted");
    }
    
    // Wait a bit for cleanup, then reinitialize
    setTimeout(async () => {
      try {
        await client.initialize();
        // QR code will be generated automatically via the 'qr' event
      } catch (err) {
        console.error("[REINIT ERROR]", err.message);
      }
    }, 2000);
    
    res.json({ success: true, message: "Disconnected. New QR code will appear shortly." });
  } catch (err) {
    console.error("[DISCONNECT ERROR]", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
});

registerRoute("post", "/send-otp", requireAuth, async (req, res) => {
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
    const msg = `رمز التحقق: ${otp}`;
    await sendMessageWithRetry(phoneNumber, msg);
    res.json({ success: true, message: "OTP sent successfully" });
  } catch (err) {
    console.error("[SEND-OTP ERROR]", err.message);
    res.status(500).json({
      success: false,
      message: "Failed to send OTP: " + err.message,
    });
  }
});

registerRoute("post", "/send-message", requireAuth, async (req, res) => {
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
    await sendMessageWithRetry(phoneNumber, message);
    res.json({ success: true, message: "Message sent successfully" });
  } catch (err) {
    console.error("[SEND-MESSAGE ERROR]", err.message);
    res.status(500).json({
      success: false,
      message: "Failed to send message: " + err.message,
    });
  }
});

// Serve static files from public directory (must be last, after all API routes)
app.use(express.static(path.join(__dirname, "public")));

client.initialize().catch(err => {
  console.error("[INIT ERROR]", err.message);
});

app.listen(port, "0.0.0.0", () => {
  console.log(`[SERVER] Running on http://0.0.0.0:${port}`);
  console.log(`[SERVER] Routes registered with /otp-service prefix support`);
});

process.on("SIGINT", async () => {
  console.log("[SHUTDOWN] Closing...");
  await client.destroy();
  process.exit(0);
});