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
let isManualDisconnect = false; // Flag to prevent auto-reconnect on manual disconnect

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
  console.log("[QR] QR code generated! Length:", qr ? qr.length : 0);
  if (qr) {
    qrcode.generate(qr, { small: true });
    currentQR = qr; 
    console.log("[QR] currentQR set successfully, length:", currentQR.length);
  } else {
    console.log("[QR] WARNING: QR code is null or undefined!");
    currentQR = null;
  }
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
  currentQR = null; // Clear QR on disconnect
  
  // Don't auto-reconnect if it was a manual disconnect
  if (isManualDisconnect) {
    console.log("[DISCONNECT] Manual disconnect - not auto-reconnecting");
    isManualDisconnect = false; // Reset flag
    return;
  }
  
  // Only auto-reconnect if it's an unexpected disconnect AND session still exists
  const sessionPath = path.join(AUTH_DIR, "session-default");
  if ((reason === "LOGOUT" || reason === "NAVIGATION") && fs.existsSync(sessionPath)) {
    console.log("[RECONNECT] Unexpected disconnect with session - attempting to reconnect...");
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
  } else {
    console.log("[DISCONNECT] No session found or not a reconnectable reason - not auto-reconnecting");
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
  
  const sessionPath = path.join(AUTH_DIR, "session-default");
  const hasSession = fs.existsSync(sessionPath);
  
  console.log("[QR API] Request received. Current state:", {
    hasQR: currentQR !== null,
    qrLength: currentQR ? currentQR.length : 0,
    isReady: isClientReady,
    isAuthenticated: isAuthenticated,
    hasSession: hasSession,
    clientInitialized: clientInitialized,
    isManualDisconnect: isManualDisconnect
  });
  
  // CRITICAL: WhatsApp Web.js only generates QR codes when there's NO session
  // If a session exists, it authenticates automatically and skips QR generation
  // So if we need a QR code, we must ensure there's no session
  
  // If client is ready/authenticated, no QR is needed
  if (isClientReady || isAuthenticated) {
    console.log("[QR API] Client is ready/authenticated - no QR needed");
    return res.status(200).json({ 
      qr: null,
      ready: isClientReady,
      authenticated: isAuthenticated,
      timestamp: new Date().toISOString()
    });
  }
  
  // If session exists but client is not ready, it's authenticating (no QR will be generated)
  if (hasSession) {
    console.log("[QR API] Session exists - client will authenticate automatically, no QR will be generated");
    return res.status(200).json({ 
      qr: null,
      ready: false,
      authenticated: false,
      message: "Session exists - authenticating automatically. No QR code available.",
      timestamp: new Date().toISOString()
    });
  }
  
  // No session exists - QR should be generated
  if (!hasSession && !currentQR) {
    console.log("[QR API] No session and no QR - ensuring client is initialized to generate QR...");
    
    // Initialize client if not already initialized (will generate QR since no session)
    if (!clientInitialized && !isManualDisconnect) {
      console.log("[QR API] Initializing client to generate QR code...");
      initializeClientIfNeeded();
    } else if (isManualDisconnect) {
      console.log("[QR API] Manual disconnect in progress - client will not initialize");
    } else {
      console.log("[QR API] Client already initialized, waiting for QR generation...");
    }
  }
  
  // Return current QR status
  console.log("[QR API] Returning QR status:", {
    hasQR: currentQR !== null,
    qrLength: currentQR ? currentQR.length : 0
  });
  
  res.status(200).json({ 
    qr: currentQR || null,
    ready: isClientReady,
    authenticated: isAuthenticated,
    timestamp: new Date().toISOString()
  });
});

registerRoute("post", "/api/disconnect", requireAuth, async (req, res) => {
  try {
    // Set manual disconnect flag FIRST to prevent auto-reconnect
    isManualDisconnect = true;
    clientInitialized = false; // Mark as not initialized
    console.log("[DISCONNECT] Manual disconnect initiated, flag set to prevent auto-reconnect");
    
    // Clear state first
    currentQR = null;
    isAuthenticated = false;
    isClientReady = false;
    reconnectAttempts = 0;
    
    // Destroy the client FIRST to prevent it from recreating session
    try {
      console.log("[DISCONNECT] Destroying client first...");
      await client.destroy();
      clientInitialized = false;
      console.log("[DISCONNECT] Client destroyed successfully");
      // Wait for cleanup
      await new Promise(resolve => setTimeout(resolve, 2000));
    } catch (err) {
      console.log("[DISCONNECT] Error destroying client (may already be destroyed):", err.message);
      clientInitialized = false;
    }
    
    // Delete the session directory AFTER destroying client
    const sessionPath = path.join(AUTH_DIR, "session-default");
    if (fs.existsSync(sessionPath)) {
      console.log("[DISCONNECT] Deleting session directory:", sessionPath);
      fs.rmSync(sessionPath, { recursive: true, force: true });
      console.log("[DISCONNECT] Session directory deleted");
      
      // Verify deletion with retries
      await new Promise(resolve => setTimeout(resolve, 500));
      let retries = 0;
      while (fs.existsSync(sessionPath) && retries < 3) {
        console.log(`[DISCONNECT] Session still exists, retrying deletion (${retries + 1}/3)...`);
        fs.rmSync(sessionPath, { recursive: true, force: true });
        await new Promise(resolve => setTimeout(resolve, 500));
        retries++;
      }
      
      if (fs.existsSync(sessionPath)) {
        console.error("[DISCONNECT] ERROR: Session directory still exists after multiple deletion attempts!");
      } else {
        console.log("[DISCONNECT] Session directory confirmed deleted");
      }
    } else {
      console.log("[DISCONNECT] No session directory found to delete");
    }
    
    // Notify SSE clients about disconnection
    const message = JSON.stringify({ 
      type: 'disconnected', 
      message: 'WhatsApp disconnected successfully',
      timestamp: new Date().toISOString()
    });
    sseClients.forEach(client => {
      try {
        client.write(`data: ${message}\n\n`);
      } catch (err) {
        console.error('[SSE] Error sending to client:', err);
      }
    });
    
    res.json({ success: true, message: "Disconnected successfully. Click 'Reconnect' to generate a new QR code." });
  } catch (err) {
    console.error("[DISCONNECT ERROR]", err.message);
    isManualDisconnect = false; // Reset flag on error
    clientInitialized = false;
    res.status(500).json({ success: false, message: err.message });
  }
});

// Reconnect endpoint - manually initialize client to generate new QR code
registerRoute("post", "/api/reconnect", requireAuth, async (req, res) => {
  try {
    // Reset manual disconnect flag and mark client as needing initialization
    isManualDisconnect = false;
    reconnectAttempts = 0;
    clientInitialized = false;
    
    // Ensure session is deleted before reconnecting (CRITICAL for QR generation)
    const sessionPath = path.join(AUTH_DIR, "session-default");
    if (fs.existsSync(sessionPath)) {
      console.log("[RECONNECT] Removing existing session to force QR generation...");
      fs.rmSync(sessionPath, { recursive: true, force: true });
      // Double-check deletion
      if (fs.existsSync(sessionPath)) {
        console.error("[RECONNECT] ERROR: Session still exists after deletion!");
        // Try again with more force
        fs.rmSync(sessionPath, { recursive: true, force: true, maxRetries: 3 });
      } else {
        console.log("[RECONNECT] Session removed successfully");
      }
    } else {
      console.log("[RECONNECT] No session found (good, will generate QR)");
    }
    
    // If client is already initialized, destroy it first
    try {
      console.log("[RECONNECT] Destroying existing client...");
      await client.destroy();
      clientInitialized = false;
      // Wait for cleanup
      await new Promise(resolve => setTimeout(resolve, 2000));
    } catch (err) {
      console.log("[RECONNECT] Client already destroyed or error:", err.message);
      clientInitialized = false;
    }
    
    // Clear state
    currentQR = null;
    isAuthenticated = false;
    isClientReady = false;
    
    console.log("[RECONNECT] Initializing client to generate QR code (no session = will generate QR)...");
    
    // Initialize client to generate new QR code (no session = will generate QR)
    client.initialize().then(() => {
      console.log("[RECONNECT] Client initialization started");
      clientInitialized = true;
    }).catch(err => {
      console.error("[RECONNECT INIT ERROR]", err.message);
      clientInitialized = false;
    });
    
    // Wait for QR to be generated (it's async, can take a few seconds)
    let qrGenerated = false;
    for (let i = 0; i < 20; i++) { // Wait up to 10 seconds
      await new Promise(resolve => setTimeout(resolve, 500));
      if (currentQR) {
        qrGenerated = true;
        console.log("[RECONNECT] QR code generated successfully! Length:", currentQR.length);
        break;
      }
      console.log(`[RECONNECT] Waiting for QR... (${i + 1}/20)`);
    }
    
    if (qrGenerated) {
      res.json({ success: true, message: "Reconnected! QR code is ready.", qr: currentQR });
    } else {
      console.log("[RECONNECT] QR code not generated yet, but initialization started");
      res.json({ success: true, message: "Reconnecting... QR code will appear shortly." });
    }
  } catch (err) {
    console.error("[RECONNECT ERROR]", err.message);
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

// Initialize client on server start ONLY if not manually disconnected
// We'll initialize it lazily when needed
let clientInitialized = false;

function initializeClientIfNeeded() {
  if (clientInitialized || isManualDisconnect) {
    if (isManualDisconnect) {
      console.log("[INIT] Skipping initialization - manual disconnect in progress");
    }
    return;
  }
  
  console.log("[INIT] Starting WhatsApp client initialization...");
  const sessionPath = path.join(AUTH_DIR, "session-default");
  if (fs.existsSync(sessionPath)) {
    console.log("[INIT] Existing session found, client will try to authenticate automatically (NO QR will be generated)");
  } else {
    console.log("[INIT] No session found, QR code WILL be generated");
  }

  client.initialize().then(() => {
    console.log("[INIT] Client initialization started successfully");
    clientInitialized = true;
  }).catch(err => {
    console.error("[INIT ERROR]", err.message);
    console.error("[INIT ERROR] Stack:", err.stack);
    clientInitialized = false;
  });
}

// Initialize on server start (only if not manually disconnected)
if (!isManualDisconnect) {
  initializeClientIfNeeded();
} else {
  console.log("[INIT] Server start - skipping initialization due to manual disconnect");
}

app.listen(port, "0.0.0.0", () => {
  console.log(`[SERVER] Running on http://0.0.0.0:${port}`);
  console.log(`[SERVER] Routes registered with /otp-service prefix support`);
});

process.on("SIGINT", async () => {
  console.log("[SHUTDOWN] Closing...");
  await client.destroy();
  process.exit(0);
});