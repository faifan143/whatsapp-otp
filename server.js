require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const { Client, LocalAuth } = require("whatsapp-web.js");
const qrcode = require("qrcode-terminal");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

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
let clientId = null;

const AUTH_DIR = "./.wwebjs_auth";

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

// ==================== KILL OLD SESSION ====================
function cleanupAuthDirectory() {
  console.log("[CLEANUP] Cleaning auth directory...");
  
  if (fs.existsSync(AUTH_DIR)) {
    try {
      const files = fs.readdirSync(AUTH_DIR);
      console.log("[CLEANUP] Found directories:", files);
      
      files.forEach(file => {
        const fullPath = path.join(AUTH_DIR, file);
        try {
          fs.rmSync(fullPath, { recursive: true, force: true });
          console.log("[CLEANUP] Deleted:", file);
        } catch (err) {
          console.error("[CLEANUP] Error deleting " + file + ":", err.message);
        }
      });
    } catch (err) {
      console.error("[CLEANUP] Error reading auth dir:", err.message);
    }
  }
  
  // Recreate empty directory
  if (!fs.existsSync(AUTH_DIR)) {
    fs.mkdirSync(AUTH_DIR, { recursive: true });
  }
  
  console.log("[CLEANUP] Auth directory is now clean");
}

// ==================== CLIENT FACTORY ====================
function createAndSetupClient(useNewId = false) {
  // FORCE NEW CLIENT ID EACH TIME
  if (useNewId) {
    clientId = crypto.randomBytes(8).toString('hex');
  } else if (!clientId) {
    clientId = 'default';
  }
  
  console.log("[CLIENT] Creating new client with ID:", clientId);
  
  client = new Client({
    authStrategy: new LocalAuth({ clientId: clientId, dataPath: AUTH_DIR }),
    puppeteer: puppeteerConfig,
    webVersionCache: {
      type: "remote",
      remotePath: "https://raw.githubusercontent.com/wppconnect-team/wa-version/main/html/2.2413.51-beta.html",
    },
  });

  // QR Event - PRIORITY 1
  let qrHandler = (qr) => {
    console.log("[EVENT] ▓▓▓ QR CODE GENERATED ▓▓▓");
    qrEventFired = true;
    currentQR = qr || null;
    
    if (qr) {
      qrcode.generate(qr, { small: true });
      console.log("[EVENT] QR length:", qr.length);
    }
    
    isAuthenticated = false;
    isClientReady = false;
    
    broadcastSSE({ type: 'qr_generated', message: 'QR' });
  };
  client.on("qr", qrHandler);

  // Authenticated Event - PRIORITY 2
  let authHandler = () => {
    console.log("[EVENT] ░░░ AUTHENTICATED (NOT WHAT WE WANT) ░░░");
    console.log("[EVENT] This means old session was reused!");
    isAuthenticated = true;
    
    broadcastSSE({ type: 'qr_scanned', message: 'QR scanned' });
  };
  client.on("authenticated", authHandler);

  // Ready Event - PRIORITY 3
  let readyHandler = () => {
    console.log("[EVENT] ███ READY ███");
    isClientReady = true;
    isAuthenticated = true;
    currentQR = null;
    
    broadcastSSE({ type: 'ready', message: 'Ready' });
  };
  client.on("ready", readyHandler);

  // Disconnected Event
  let disconnectHandler = (reason) => {
    console.log("[EVENT] DISCONNECTED:", reason);
    isAuthenticated = false;
    isClientReady = false;
    currentQR = null;
    qrEventFired = false;
    
    broadcastSSE({ type: 'disconnected', message: 'Disconnected' });
  };
  client.on("disconnected", disconnectHandler);

  // Auth Failure
  let failHandler = (msg) => {
    console.log("[EVENT] Auth failure:", msg);
    isAuthenticated = false;
    isClientReady = false;
    qrEventFired = false;
  };
  client.on("auth_failure", failHandler);

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
    clientId: clientId,
  });
});

// ==================== ULTIMATE QR ENDPOINT ====================
registerRoute("get", "/api/qr", requireAuth, async (req, res) => {
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  
  try {
    console.log("\n");
    console.log("╔════════════════════════════════════════════╗");
    console.log("║           QR REQUEST RECEIVED              ║");
    console.log("╚════════════════════════════════════════════╝");
    console.log("[QR] State: qr=" + (currentQR ? "YES" : "NO") + 
                " ready=" + isClientReady + 
                " auth=" + isAuthenticated + 
                " fired=" + qrEventFired);
    
    // If already ready, no QR needed
    if (isClientReady) {
      console.log("[QR] Already ready, returning null");
      return res.json({ qr: null, ready: true, authenticated: true });
    }
    
    // If we have a QR that actually fired, return it
    if (currentQR && qrEventFired) {
      console.log("[QR] Returning existing QR");
      return res.json({ qr: currentQR, ready: false, authenticated: false });
    }
    
    // NUCLEAR CLEANUP - Delete all old sessions
    console.log("[QR] Performing nuclear cleanup...");
    cleanupAuthDirectory();
    
    // Create fresh client with NEW ID
    console.log("[QR] Creating fresh client with new ID...");
    createAndSetupClient(true);
    
    // Reset all flags
    qrEventFired = false;
    currentQR = null;
    isAuthenticated = false;
    isClientReady = false;
    
    console.log("[QR] Initializing client...");
    
    try {
      await client.initialize();
      console.log("[QR] Client initialization call completed");
    } catch (err) {
      console.error("[QR] Init error:", err.message);
    }
    
    // WAIT FOR QR EVENT (not authenticated event!)
    console.log("[QR] Waiting for QR event (max 25 seconds)...");
    const startTime = Date.now();
    
    while (Date.now() - startTime < 25000) {
      // Check 1: Did QR event fire?
      if (qrEventFired && currentQR) {
        console.log("[QR] ✓ SUCCESS: QR event fired!");
        return res.json({ qr: currentQR, ready: false, authenticated: false });
      }
      
      // Check 2: Did it become ready? (shouldn't happen but handle it)
      if (isClientReady) {
        console.log("[QR] ⚠ Already ready (authenticated from old session)");
        return res.json({ qr: null, ready: true, authenticated: true });
      }
      
      // Check 3: Every 5 seconds, log status
      if ((Date.now() - startTime) % 5000 < 500) {
        console.log("[QR] Still waiting... qr=" + qrEventFired + " ready=" + isClientReady);
      }
      
      await new Promise(r => setTimeout(r, 500));
    }
    
    console.log("[QR] ✗ TIMEOUT: No QR event received after 25 seconds");
    
    // If we get here, something went wrong
    res.json({ 
      qr: currentQR || null,
      ready: isClientReady,
      authenticated: isAuthenticated,
      fired: qrEventFired,
      timeout: true,
      error: "QR event did not fire"
    });
    
  } catch (error) {
    console.error("[QR] FATAL ERROR:", error.message);
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
    console.log("\n[DISCONNECT] NUCLEAR DISCONNECT INITIATED\n");
    
    // Kill everything
    currentQR = null;
    isAuthenticated = false;
    isClientReady = false;
    qrEventFired = false;
    
    if (client) {
      try {
        await client.destroy();
        console.log("[DISCONNECT] Client destroyed");
      } catch (err) {
        console.error("[DISCONNECT] Error:", err.message);
      }
      client = null;
    }
    
    // Delete ALL auth data
    cleanupAuthDirectory();
    
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
console.log("║  WhatsApp OTP - ULTIMATE QR FIX (v1.0)   ║");
console.log("╚════════════════════════════════════════════╝");
console.log("");

// Clean on startup
cleanupAuthDirectory();
createAndSetupClient(true);

const server = app.listen(port, "0.0.0.0", () => {
  console.log("[STARTUP] Server listening on port " + port);
  console.log("");
});

process.on("SIGINT", async () => {
  console.log("\n[SHUTDOWN] Shutting down gracefully...");
  if (client) {
    try {
      await client.destroy();
    } catch (e) {}
  }
  server.close();
  process.exit(0);
});