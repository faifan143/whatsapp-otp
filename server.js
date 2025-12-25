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
    res.cookie("sessionId", sessionId, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 });
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
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  
  res.write(`data: ${JSON.stringify({ type: 'connected', message: 'Connected to event stream' })}\n\n`);
  
  sseClients.add(res);
  
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
let qrPromiseResolvers = [];

const AUTH_DIR = "./.wwebjs_auth";
if (!fs.existsSync(AUTH_DIR)) fs.mkdirSync(AUTH_DIR, { recursive: true });

let isAuthenticated = false;
let isClientReady = false;
let clientInitialized = false;
let isManualDisconnect = false;
let disconnectTimeout = null;
let client = null;

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

client = createClient();

client.on("qr", (qr) => {
  console.log("[QR EVENT] QR generated");
  if (qr) {
    qrcode.generate(qr, { small: true });
    currentQR = qr;
    
    qrPromiseResolvers.forEach(resolve => resolve(qr));
    qrPromiseResolvers = [];
  } else {
    currentQR = null;
  }
  isAuthenticated = false;
  isClientReady = false;
  
  const message = JSON.stringify({ 
    type: 'qr_generated', 
    message: 'New QR code generated',
    timestamp: new Date().toISOString()
  });
  sseClients.forEach(client => {
    try {
      client.write(`data: ${message}\n\n`);
    } catch (err) {
      // Client disconnected
    }
  });
});

client.on("authenticated", () => {
  console.log("[CLIENT EVENT] Authenticated");
  isAuthenticated = true;
  
  const message = JSON.stringify({ 
    type: 'qr_scanned', 
    message: 'QR code scanned successfully!',
    timestamp: new Date().toISOString()
  });
  sseClients.forEach(client => {
    try {
      client.write(`data: ${message}\n\n`);
    } catch (err) {
      // Client disconnected
    }
  });
});

client.on("ready", () => {
  console.log("[CLIENT EVENT] Ready");
  isClientReady = true;
  isAuthenticated = true;
  currentQR = null;
  
  const message = JSON.stringify({ 
    type: 'ready', 
    message: 'WhatsApp client is ready!',
    timestamp: new Date().toISOString()
  });
  sseClients.forEach(client => {
    try {
      client.write(`data: ${message}\n\n`);
    } catch (err) {
      // Client disconnected
    }
  });
});

client.on("disconnected", async (reason) => {
  console.log("[CLIENT EVENT] Disconnected - reason:", reason);
  isAuthenticated = false;
  isClientReady = false;
  currentQR = null;
  clientInitialized = false;
  
  const message = JSON.stringify({ 
    type: 'disconnected', 
    message: 'WhatsApp client disconnected',
    timestamp: new Date().toISOString()
  });
  sseClients.forEach(client => {
    try {
      client.write(`data: ${message}\n\n`);
    } catch (err) {
      // Client disconnected
    }
  });
});

client.on("auth_failure", (msg) => {
  console.log("[CLIENT EVENT] Auth failure");
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

// API Endpoints
registerRoute("get", "/health", (req, res) => {
  res.json({
    status: "ok",
    authenticated: isAuthenticated,
    ready: isClientReady,
  });
});

registerRoute("get", "/test", (req, res) => {
  res.json({ message: "Routes are working!", path: req.path, originalUrl: req.originalUrl });
});

registerRoute("get", "/status", (req, res) => {
  res.json({
    authenticated: isAuthenticated,
    ready: isClientReady,
    timestamp: new Date().toISOString(),
  });
});

// FIXED QR API ENDPOINT
registerRoute("get", "/api/qr", requireAuth, async (req, res) => {
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.set('Content-Type', 'application/json');
  
  try {
    console.log("[QR API] Request received. Current state:", {
      hasQR: !!currentQR,
      qrLength: currentQR ? currentQR.length : 0,
      isReady: isClientReady,
      isAuthenticated: isAuthenticated,
      hasSession: fs.existsSync(path.join(AUTH_DIR, "session-default")),
      clientInitialized: clientInitialized,
      isManualDisconnect: isManualDisconnect
    });

    // If we already have a QR, return it
    if (currentQR) {
      console.log("[QR API] Returning existing QR");
      return res.json({ 
        qr: currentQR,
        ready: isClientReady,
        authenticated: isAuthenticated
      });
    }
    
    // If client is ready, don't wait for QR
    if (isClientReady) {
      console.log("[QR API] Client ready, returning null QR");
      return res.json({ 
        qr: null,
        ready: true,
        authenticated: true
      });
    }
    
    const sessionPath = path.join(AUTH_DIR, "session-default");
    const hasSession = fs.existsSync(sessionPath);
    
    console.log("[QR API] No session:", !hasSession, "Need init:", !clientInitialized);
    
    // CRITICAL FIX: Reset disconnect flag if it's been pending for too long (30+ seconds)
    if (isManualDisconnect && disconnectTimeout) {
      const timeSinceDisconnect = Date.now() - disconnectTimeout;
      if (timeSinceDisconnect > 30000) {
        console.log("[QR API] Disconnect timeout exceeded, resetting isManualDisconnect flag");
        isManualDisconnect = false;
        disconnectTimeout = null;
      }
    }

    // Initialize client if needed
    if (!hasSession && !clientInitialized && !isManualDisconnect) {
      console.log("[QR API] No session and no QR - ensuring client is initialized to generate QR...");
      clientInitialized = true;
      try {
        await client.initialize();
        console.log("[QR API] Client initialized successfully");
      } catch (err) {
        console.error("[QR API] Client initialization error:", err.message);
        clientInitialized = false;
      }
    } else if (isManualDisconnect) {
      console.log("[QR API] Manual disconnect in progress - client will not initialize");
    }
    
    // Wait for QR with timeout
    const qrPromise = new Promise((resolve) => {
      qrPromiseResolvers.push(resolve);
      setTimeout(() => {
        console.log("[QR API] QR promise timeout");
        resolve(null);
      }, 10000);
    });
    
    const qrCode = await qrPromise;
    
    console.log("[QR API] Returning QR status:", { hasQR: !!qrCode, qrLength: qrCode ? qrCode.length : 0 });
    
    res.json({ 
      qr: qrCode || currentQR || null,
      ready: isClientReady,
      authenticated: isAuthenticated
    });
  } catch (error) {
    console.error("[QR API] Error:", error.message);
    res.json({ 
      qr: currentQR || null,
      ready: isClientReady,
      authenticated: isAuthenticated,
      error: error.message
    });
  }
});

// Disconnect endpoint
registerRoute("post", "/api/disconnect", requireAuth, async (req, res) => {
  try {
    console.log("[DISCONNECT] Starting disconnect process");
    
    // Set manual disconnect flag
    isManualDisconnect = true;
    disconnectTimeout = Date.now();
    
    // Clear state
    clientInitialized = false;
    currentQR = null;
    isAuthenticated = false;
    isClientReady = false;
    
    // Reject any waiting QR promises
    qrPromiseResolvers.forEach(resolve => resolve(null));
    qrPromiseResolvers = [];
    
    // Notify SSE clients
    const disconnectMessage = JSON.stringify({ 
      type: 'disconnected', 
      message: 'WhatsApp disconnected successfully',
      timestamp: new Date().toISOString()
    });
    sseClients.forEach(client => {
      try {
        client.write(`data: ${disconnectMessage}\n\n`);
      } catch (err) {
        sseClients.delete(client);
      }
    });
    
    // Destroy client
    try {
      if (client) {
        await client.destroy();
        console.log("[DISCONNECT] Client destroyed");
      }
    } catch (err) {
      console.error("[DISCONNECT] Error destroying client:", err.message);
    }
    
    // Recreate client
    client = createClient();
    console.log("[DISCONNECT] Client recreated");
    
    // Delete session files
    const sessionPath = path.join(AUTH_DIR, "session-default");
    for (let attempt = 0; attempt < 5; attempt++) {
      try {
        if (fs.existsSync(sessionPath)) {
          fs.rmSync(sessionPath, { 
            recursive: true, 
            force: true,
            maxRetries: 5
          });
          
          await new Promise(resolve => setTimeout(resolve, 100));
          
          if (!fs.existsSync(sessionPath)) {
            console.log("[DISCONNECT] Session deleted successfully");
            break;
          }
        } else {
          break;
        }
      } catch (err) {
        console.error("[DISCONNECT] Error deleting session (attempt " + (attempt+1) + "):", err.message);
        await new Promise(resolve => setTimeout(resolve, 200));
      }
    }
    
    // Reset disconnect flag after 30 seconds to allow re-initialization
    console.log("[DISCONNECT] Will reset disconnect flag after 30 seconds");
    setTimeout(() => {
      console.log("[DISCONNECT] Resetting isManualDisconnect flag");
      isManualDisconnect = false;
      disconnectTimeout = null;
    }, 30000);
    
    res.json({ 
      success: true, 
      message: "Completely disconnected."
    });
    
  } catch (err) {
    console.error("[DISCONNECT] Error:", err.message);
    clientInitialized = false;
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
    res.status(500).json({
      success: false,
      message: "Failed to send message: " + err.message,
    });
  }
});

// Serve static files
app.use(express.static(path.join(__dirname, "public")));

// Initialize client on startup
const initialSessionPath = path.join(AUTH_DIR, "session-default");
if (!fs.existsSync(initialSessionPath)) {
  console.log("[STARTUP] No session found, initializing client");
  clientInitialized = true;
  client.initialize().catch(err => {
    console.error("[STARTUP] Client initialization error:", err.message);
    clientInitialized = false;
  });
}

app.listen(port, "0.0.0.0", () => {
  console.log(`Server running on port ${port}`);
});

process.on("SIGINT", async () => {
  if (client) {
    await client.destroy();
  }
  process.exit(0);
});