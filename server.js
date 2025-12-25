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

// ==================== STATE ====================
let currentQR = null;
let isAuthenticated = false;
let isClientReady = false;
let qrEventFired = false;
let client = null;

const AUTH_DIR = "./.wwebjs_auth";
if (!fs.existsSync(AUTH_DIR)) {
  fs.mkdirSync(AUTH_DIR, { recursive: true });
}

// ==================== CHROMIUM ====================
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
  console.log("[CHROMIUM] Using bundled");
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
  ],
};

if (chromiumPath) {
  puppeteerConfig.executablePath = chromiumPath;
}

// ==================== CLIENT SETUP ====================
function createAndSetupClient() {
  console.log("[CLIENT] Creating new client instance");
  
  client = new Client({
    authStrategy: new LocalAuth({ clientId: "default", dataPath: AUTH_DIR }),
    puppeteer: puppeteerConfig,
    webVersionCache: {
      type: "remote",
      remotePath: "https://raw.githubusercontent.com/wppconnect-team/wa-version/main/html/2.2413.51-beta.html",
    },
  });

  // QR Event
  client.on("qr", (qr) => {
    console.log("[EVENT] === QR CODE GENERATED ===");
    qrEventFired = true;
    if (qr) {
      qrcode.generate(qr, { small: true });
      currentQR = qr;
      console.log("[EVENT] QR length:", qr.length);
    } else {
      console.log("[EVENT] QR is null/empty");
      currentQR = null;
    }
    isAuthenticated = false;
    isClientReady = false;
    
    broadcastSSE({
      type: 'qr_generated',
      message: 'QR code generated'
    });
  });

  // Authenticated Event
  client.on("authenticated", () => {
    console.log("[EVENT] === AUTHENTICATED ===");
    isAuthenticated = true;
    
    broadcastSSE({
      type: 'qr_scanned',
      message: 'QR scanned'
    });
  });

  // Ready Event
  client.on("ready", () => {
    console.log("[EVENT] === READY ===");
    isClientReady = true;
    isAuthenticated = true;
    currentQR = null;
    
    broadcastSSE({
      type: 'ready',
      message: 'Ready'
    });
  });

  // Disconnected Event
  client.on("disconnected", (reason) => {
    console.log("[EVENT] === DISCONNECTED ===", reason);
    isAuthenticated = false;
    isClientReady = false;
    currentQR = null;
    qrEventFired = false;
    
    broadcastSSE({
      type: 'disconnected',
      message: 'Disconnected'
    });
  });

  client.on("auth_failure", (msg) => {
    console.log("[EVENT] Auth failure:", msg);
    isAuthenticated = false;
    isClientReady = false;
    qrEventFired = false;
  });

  return client;
}

// ==================== BROADCAST ====================
function broadcastSSE(data) {
  sseClients.forEach(res => {
    try {
      res.write(`data: ${JSON.stringify(data)}\n\n`);
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
    return res.status(500).json({ error: "Login not configured" });
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
    hasQR: currentQR !== null,
    qrEventFired: qrEventFired,
  });
});

// ==================== QR ENDPOINT - NUCLEAR VERSION ====================
registerRoute("get", "/api/qr", requireAuth, async (req, res) => {
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  
  try {
    console.log("[QR REQUEST] ================================================");
    console.log("[QR REQUEST] hasQR:", !!currentQR);
    console.log("[QR REQUEST] isReady:", isClientReady);
    console.log("[QR REQUEST] isAuthenticated:", isAuthenticated);
    console.log("[QR REQUEST] qrEventFired:", qrEventFired);
    
    // If ready, no need for QR
    if (isClientReady) {
      console.log("[QR REQUEST] Client ready, returning null");
      return res.json({ qr: null, ready: true, authenticated: true });
    }
    
    // If we have a QR, return it
    if (currentQR && qrEventFired) {
      console.log("[QR REQUEST] Returning existing QR");
      return res.json({ qr: currentQR, ready: false, authenticated: isAuthenticated });
    }
    
    // Initialize if client doesn't exist
    if (!client) {
      console.log("[QR REQUEST] No client, creating...");
      createAndSetupClient();
    }
    
    // Reset flags for fresh QR
    qrEventFired = false;
    currentQR = null;
    
    console.log("[QR REQUEST] Initializing client...");
    
    try {
      // This will trigger "qr" event if no session, or "authenticated" if session exists
      await client.initialize();
      console.log("[QR REQUEST] Client initialized");
    } catch (err) {
      console.error("[QR REQUEST] Init error:", err.message);
      // Continue anyway, event might still fire
    }
    
    // Wait for QR event (20 second timeout)
    console.log("[QR REQUEST] Waiting for QR event...");
    const startTime = Date.now();
    
    while (Date.now() - startTime < 20000) {
      if (currentQR && qrEventFired) {
        console.log("[QR REQUEST] QR received!");
        return res.json({ qr: currentQR, ready: false, authenticated: false });
      }
      
      if (isClientReady) {
        console.log("[QR REQUEST] Client became ready (authenticated)");
        return res.json({ qr: null, ready: true, authenticated: true });
      }
      
      await new Promise(r => setTimeout(r, 500));
    }
    
    console.log("[QR REQUEST] Timeout waiting for QR");
    res.json({ 
      qr: currentQR || null, 
      ready: isClientReady, 
      authenticated: isAuthenticated,
      timeout: true
    });
    
  } catch (error) {
    console.error("[QR REQUEST] ERROR:", error.message);
    res.json({ 
      qr: null, 
      error: error.message,
      ready: false,
      authenticated: false
    });
  }
});

// ==================== DISCONNECT ====================
registerRoute("post", "/api/disconnect", requireAuth, async (req, res) => {
  try {
    console.log("[DISCONNECT] Starting nuclear disconnect");
    
    // Reset all state
    currentQR = null;
    isAuthenticated = false;
    isClientReady = false;
    qrEventFired = false;
    
    // Destroy client
    if (client) {
      try {
        await client.destroy();
        console.log("[DISCONNECT] Client destroyed");
      } catch (err) {
        console.error("[DISCONNECT] Destroy error:", err.message);
      }
      client = null;
    }
    
    // Delete session files
    const sessionPath = path.join(AUTH_DIR, "session-default");
    if (fs.existsSync(sessionPath)) {
      try {
        fs.rmSync(sessionPath, { recursive: true, force: true });
        console.log("[DISCONNECT] Session files deleted");
      } catch (err) {
        console.error("[DISCONNECT] Delete error:", err.message);
      }
    }
    
    broadcastSSE({ type: 'disconnected', message: 'Disconnected' });
    
    res.json({ success: true, message: "Disconnected" });
    
  } catch (err) {
    console.error("[DISCONNECT] Error:", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
});

// ==================== MESSAGING ====================
function formatPhone(phone) {
  let num = phone.toString().trim().replace(/[^0-9]/g, "");
  if (num.startsWith("0")) num = "963" + num.substring(1);
  if (num.length < 10) num = "963" + num;
  return num;
}

async function getChatId(phoneNumber) {
  try {
    const formatted = formatPhone(phoneNumber);
    const numberId = await client.getNumberId(formatted);
    return numberId ? numberId._serialized : formatted + "@c.us";
  } catch {
    return formatPhone(phoneNumber) + "@c.us";
  }
}

registerRoute("post", "/send-message", requireAuth, async (req, res) => {
  const { phoneNumber, message } = req.body;
  if (!phoneNumber || !message) {
    return res.status(400).json({ success: false, message: "Missing params" });
  }
  if (!isClientReady) {
    return res.status(503).json({ success: false, message: "Not ready" });
  }
  try {
    const chatId = await getChatId(phoneNumber);
    await client.sendMessage(chatId, message);
    res.json({ success: true, message: "Sent" });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

registerRoute("post", "/send-otp", requireAuth, async (req, res) => {
  const { phoneNumber, otp } = req.body;
  if (!phoneNumber || !otp) {
    return res.status(400).json({ success: false, message: "Missing params" });
  }
  if (!isClientReady) {
    return res.status(503).json({ success: false, message: "Not ready" });
  }
  try {
    const msg = `رمز التحقق: ${otp}`;
    const chatId = await getChatId(phoneNumber);
    await client.sendMessage(chatId, msg);
    res.json({ success: true, message: "Sent" });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ==================== STATIC ====================
app.use(express.static(path.join(__dirname, "public")));

// ==================== STARTUP ====================
console.log("");
console.log("╔════════════════════════════════════════════╗");
console.log("║     WhatsApp OTP Service - NUCLEAR V2     ║");
console.log("╚════════════════════════════════════════════╝");
console.log("");
console.log("[STARTUP] Creating initial client...");
createAndSetupClient();

const server = app.listen(port, "0.0.0.0", () => {
  console.log("[STARTUP] Server listening on port " + port);
});

process.on("SIGINT", async () => {
  console.log("[SHUTDOWN] Shutting down...");
  if (client) {
    try {
      await client.destroy();
    } catch (e) {}
  }
  server.close();
  process.exit(0);
});