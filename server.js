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

// Sessions
const sessions = new Set();
const sseClients = new Set();

const requireAuth = (req, res, next) => {
  const sessionId = req.cookies.sessionId;
  if (sessionId && sessions.has(sessionId)) {
    return next();
  }
  res.status(401).json({ error: 'Unauthorized' });
};

function registerRoute(method, path, ...handlers) {
  const wrappedHandlers = handlers.map(handler => {
    return async (req, res, next) => {
      try {
        const result = handler(req, res, next);
        if (result && typeof result.then === 'function') {
          await result;
        }
      } catch (error) {
        if (!res.headersSent) {
          res.status(500).json({ error: error.message || 'Internal server error' });
        }
      }
    };
  });
  
  app[method](path, ...wrappedHandlers);
  app[method](`/otp-service${path}`, ...wrappedHandlers);
}

// ==================== STATE MANAGEMENT ====================
let currentQR = null;
let isAuthenticated = false;
let isClientReady = false;
let clientInitialized = false;
let initializationInProgress = false;
let isManualDisconnect = false;
let disconnectTimeout = null;

const AUTH_DIR = "./.wwebjs_auth";
if (!fs.existsSync(AUTH_DIR)) fs.mkdirSync(AUTH_DIR, { recursive: true });

let client = null;

// ==================== CHROMIUM DETECTION ====================
const getChromiumPath = () => {
  const possiblePaths = [
    "/usr/bin/chromium-browser",
    "/usr/bin/chromium",
    "/snap/bin/chromium",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
  ];
  
  for (const chromiumPath of possiblePaths) {
    if (fs.existsSync(chromiumPath)) {
      console.log("[CHROMIUM] Found at:", chromiumPath);
      return chromiumPath;
    }
  }
  console.log("[CHROMIUM] Using bundled Chromium");
  return undefined;
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

if (chromiumPath) {
  puppeteerConfig.executablePath = chromiumPath;
}

// ==================== CLIENT CREATION ====================
function createClient() {
  return new Client({
    authStrategy: new LocalAuth({ clientId: "default", dataPath: AUTH_DIR }),
    puppeteer: puppeteerConfig,
    webVersionCache: {
      type: "remote",
      remotePath: "https://raw.githubusercontent.com/wppconnect-team/wa-version/main/html/2.2413.51-beta.html",
    },
  });
}

function setupClientEvents() {
  console.log("[CLIENT SETUP] Setting up event handlers");
  
  client.on("qr", (qr) => {
    console.log("[EVENT] QR Generated");
    if (qr) {
      qrcode.generate(qr, { small: true });
      currentQR = qr;
    } else {
      currentQR = null;
    }
    isAuthenticated = false;
    isClientReady = false;
    
    // Notify SSE
    broadcastSSE({
      type: 'qr_generated',
      message: 'New QR code generated',
      timestamp: new Date().toISOString()
    });
  });

  client.on("authenticated", () => {
    console.log("[EVENT] Authenticated");
    isAuthenticated = true;
    
    broadcastSSE({
      type: 'qr_scanned',
      message: 'QR code scanned successfully!',
      timestamp: new Date().toISOString()
    });
  });

  client.on("ready", () => {
    console.log("[EVENT] Ready");
    isClientReady = true;
    isAuthenticated = true;
    currentQR = null;
    
    broadcastSSE({
      type: 'ready',
      message: 'WhatsApp client is ready!',
      timestamp: new Date().toISOString()
    });
  });

  client.on("disconnected", async (reason) => {
    console.log("[EVENT] Disconnected - reason:", reason);
    isAuthenticated = false;
    isClientReady = false;
    currentQR = null;
    
    broadcastSSE({
      type: 'disconnected',
      message: 'WhatsApp client disconnected',
      timestamp: new Date().toISOString()
    });
  });

  client.on("auth_failure", (msg) => {
    console.log("[EVENT] Auth failure");
    isAuthenticated = false;
    isClientReady = false;
  });
}

// ==================== INITIALIZATION ====================
async function ensureClientInitialized() {
  // Prevent concurrent initialization
  if (initializationInProgress) {
    console.log("[INIT] Initialization already in progress, waiting...");
    // Wait for it to complete
    for (let i = 0; i < 50; i++) {
      if (!initializationInProgress) break;
      await new Promise(r => setTimeout(r, 100));
    }
    return;
  }

  if (clientInitialized && client) {
    console.log("[INIT] Client already initialized");
    return;
  }

  if (isManualDisconnect) {
    console.log("[INIT] Manual disconnect in progress, skipping initialization");
    return;
  }

  initializationInProgress = true;
  
  try {
    console.log("[INIT] Starting client initialization...");
    
    if (!client) {
      console.log("[INIT] Creating new client");
      client = createClient();
      setupClientEvents();
    }

    console.log("[INIT] Calling client.initialize()");
    await client.initialize();
    
    clientInitialized = true;
    console.log("[INIT] Client initialized successfully");
    
  } catch (error) {
    console.error("[INIT] ERROR during initialization:", error.message);
    clientInitialized = false;
    
    // Try to recover by recreating client
    try {
      if (client) {
        await client.destroy().catch(() => {});
      }
    } catch (e) {}
    
    client = createClient();
    setupClientEvents();
    
  } finally {
    initializationInProgress = false;
  }
}

// ==================== SSE BROADCAST ====================
function broadcastSSE(data) {
  const message = JSON.stringify(data);
  sseClients.forEach(res => {
    try {
      res.write(`data: ${message}\n\n`);
    } catch (err) {
      sseClients.delete(res);
    }
  });
}

// ==================== ROUTES ====================

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
    res.cookie("sessionId", sessionId, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 });
    res.json({ success: true });
  } else {
    res.status(401).json({ error: "Invalid credentials" });
  }
});

registerRoute("get", "/api/auth/check", (req, res) => {
  const sessionId = req.cookies.sessionId;
  res.json({ authenticated: sessionId && sessions.has(sessionId) });
});

registerRoute("get", "/api/events", requireAuth, (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  
  res.write(`data: ${JSON.stringify({ type: 'connected' })}\n\n`);
  
  sseClients.add(res);
  
  const status = {
    type: 'status',
    data: {
      authenticated: isAuthenticated,
      ready: isClientReady,
      hasQR: currentQR !== null
    }
  };
  res.write(`data: ${JSON.stringify(status)}\n\n`);
  
  req.on('close', () => {
    sseClients.delete(res);
  });
  
  const heartbeat = setInterval(() => {
    try {
      res.write(`: heartbeat\n\n`);
    } catch (err) {
      clearInterval(heartbeat);
      sseClients.delete(res);
    }
  }, 30000);
  
  req.on('close', () => {
    clearInterval(heartbeat);
  });
});

registerRoute("post", "/api/logout", (req, res) => {
  const sessionId = req.cookies.sessionId;
  if (sessionId) {
    sessions.delete(sessionId);
  }
  res.clearCookie("sessionId");
  res.json({ success: true });
});

registerRoute("get", "/status", (req, res) => {
  res.json({
    authenticated: isAuthenticated,
    ready: isClientReady,
    timestamp: new Date().toISOString(),
  });
});

registerRoute("get", "/health", (req, res) => {
  res.json({
    status: "ok",
    authenticated: isAuthenticated,
    ready: isClientReady,
  });
});

// ==================== QR CODE ENDPOINT ====================
registerRoute("get", "/api/qr", requireAuth, async (req, res) => {
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  
  try {
    console.log("[QR] Request received");
    console.log("[QR] Current state: qr=" + (currentQR ? currentQR.substring(0, 20) + "..." : "null") + 
                ", ready=" + isClientReady + ", auth=" + isAuthenticated);
    
    // If client is already ready, no QR needed
    if (isClientReady) {
      console.log("[QR] Client ready, returning null");
      return res.json({ 
        qr: null,
        ready: true,
        authenticated: true
      });
    }
    
    // Reset stale disconnect flag
    if (isManualDisconnect && disconnectTimeout) {
      const elapsed = Date.now() - disconnectTimeout;
      if (elapsed > 30000) {
        console.log("[QR] Resetting stale disconnect flag (elapsed: " + elapsed + "ms)");
        isManualDisconnect = false;
        disconnectTimeout = null;
      }
    }
    
    // Ensure client is initialized
    console.log("[QR] Ensuring client initialization...");
    await ensureClientInitialized();
    
    // If we have a QR now, return it
    if (currentQR) {
      console.log("[QR] Returning existing QR");
      return res.json({ 
        qr: currentQR,
        ready: isClientReady,
        authenticated: isAuthenticated
      });
    }
    
    // Wait for QR with timeout
    console.log("[QR] Waiting for QR generation (max 15s)");
    const qrCode = await waitForQR(15000);
    
    res.json({
      qr: qrCode || currentQR || null,
      ready: isClientReady,
      authenticated: isAuthenticated
    });
    
  } catch (error) {
    console.error("[QR] Error:", error.message);
    res.json({ 
      qr: currentQR || null,
      ready: isClientReady,
      authenticated: isAuthenticated,
      error: error.message
    });
  }
});

// Wait for QR code with proper promise handling
function waitForQR(timeoutMs = 15000) {
  return new Promise((resolve) => {
    const checkInterval = setInterval(() => {
      if (currentQR) {
        clearInterval(checkInterval);
        clearTimeout(timeoutTimer);
        console.log("[QR WAIT] QR received");
        resolve(currentQR);
      }
    }, 500);
    
    const timeoutTimer = setTimeout(() => {
      clearInterval(checkInterval);
      console.log("[QR WAIT] Timeout after " + timeoutMs + "ms");
      resolve(null);
    }, timeoutMs);
  });
}

// ==================== DISCONNECT ====================
registerRoute("post", "/api/disconnect", requireAuth, async (req, res) => {
  try {
    console.log("[DISCONNECT] Starting disconnect");
    
    isManualDisconnect = true;
    disconnectTimeout = Date.now();
    clientInitialized = false;
    isAuthenticated = false;
    isClientReady = false;
    currentQR = null;
    
    broadcastSSE({
      type: 'disconnected',
      message: 'WhatsApp disconnected',
      timestamp: new Date().toISOString()
    });
    
    // Destroy client
    if (client) {
      try {
        await client.destroy();
        console.log("[DISCONNECT] Client destroyed");
      } catch (err) {
        console.error("[DISCONNECT] Error destroying client:", err.message);
      }
    }
    
    // Delete auth files
    const sessionPath = path.join(AUTH_DIR, "session-default");
    if (fs.existsSync(sessionPath)) {
      try {
        fs.rmSync(sessionPath, { recursive: true, force: true });
        console.log("[DISCONNECT] Session deleted");
      } catch (err) {
        console.error("[DISCONNECT] Error deleting session:", err.message);
      }
    }
    
    // Recreate client for future use
    client = createClient();
    setupClientEvents();
    
    // Auto-reset flag after 30 seconds
    setTimeout(() => {
      console.log("[DISCONNECT] Auto-resetting disconnect flag");
      isManualDisconnect = false;
      disconnectTimeout = null;
    }, 30000);
    
    res.json({ 
      success: true, 
      message: "Disconnected successfully"
    });
    
  } catch (err) {
    console.error("[DISCONNECT] Error:", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
});

// ==================== MESSAGING ====================
function formatPhoneToE164(phone) {
  let num = phone.toString().trim();
  if (num.startsWith("+")) num = num.substring(1);
  num = num.replace(/[^0-9]/g, "");
  if (num.startsWith("0")) num = "963" + num.substring(1);
  if (num.length < 10) num = "963" + num;
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
      const result = await client.sendMessage(chatId, text);
      return result;
    } catch (err) {
      lastError = err;
      if (err.message.includes("LID") || err.message.includes("No LID")) {
        await new Promise(r => setTimeout(r, 3000));
      } else if (i < maxRetries - 1) {
        await new Promise(r => setTimeout(r, 2000));
      }
    }
  }
  throw lastError;
}

registerRoute("post", "/send-otp", requireAuth, async (req, res) => {
  const { phoneNumber, otp } = req.body;
  if (!phoneNumber || !otp) {
    return res.status(400).json({
      success: false,
      message: "Phone number and OTP required",
    });
  }
  if (!isClientReady) {
    return res.status(503).json({
      success: false,
      message: "WhatsApp not ready",
    });
  }
  try {
    const msg = `رمز التحقق: ${otp}`;
    await sendMessageWithRetry(phoneNumber, msg);
    res.json({ success: true, message: "OTP sent successfully" });
  } catch (err) {
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
      message: "WhatsApp not ready",
    });
  }
  try {
    await sendMessageWithRetry(phoneNumber, message);
    res.json({ success: true, message: "Message sent successfully" });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: "Failed to send message: " + err.message,
    });
  }
});

// ==================== STATIC FILES ====================
app.use(express.static(path.join(__dirname, "public")));

// ==================== STARTUP ====================
async function startup() {
  console.log("[STARTUP] Server starting on port " + port);
  
  // Create initial client
  client = createClient();
  setupClientEvents();
  
  // Initialize if no session exists
  const sessionPath = path.join(AUTH_DIR, "session-default");
  if (!fs.existsSync(sessionPath)) {
    console.log("[STARTUP] No session found, initializing client");
    ensureClientInitialized().catch(err => {
      console.error("[STARTUP] Initialization error:", err.message);
    });
  } else {
    console.log("[STARTUP] Session found, client will initialize on first QR request");
  }
}

const server = app.listen(port, "0.0.0.0", startup);

process.on("SIGINT", async () => {
  console.log("[SHUTDOWN] Shutting down gracefully");
  if (client) {
    try {
      await client.destroy();
    } catch (e) {}
  }
  server.close();
  process.exit(0);
});