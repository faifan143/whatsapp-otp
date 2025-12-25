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
  if (qr) {
    qrcode.generate(qr, { small: true });
    currentQR = qr; 
  } else {
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
      // Client disconnected
    }
  });
});

client.on("authenticated", () => {
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
      // Client disconnected
    }
  });
});

client.on("ready", () => {
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
      // Client disconnected
    }
  });
});

client.on("disconnected", async (reason) => {
  isAuthenticated = false;
  isClientReady = false;
  currentQR = null; // Clear QR on disconnect
  
  // Don't auto-reconnect if it was a manual disconnect
  if (isManualDisconnect) {
    isManualDisconnect = false; // Reset flag
    return;
  }
  
  // Only auto-reconnect if it's an unexpected disconnect AND session still exists
  const sessionPath = path.join(AUTH_DIR, "session-default");
  if ((reason === "LOGOUT" || reason === "NAVIGATION") && fs.existsSync(sessionPath)) {
    if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
      reconnectAttempts++;
      setTimeout(() => {
        client.initialize().catch(err => {
          // Reconnection failed
        });
      }, 5000 * reconnectAttempts);
    }
  }
});

client.on("auth_failure", (msg) => {
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
  
  // If client is ready/authenticated, no QR is needed
  if (isClientReady || isAuthenticated) {
    return res.status(200).json({ 
      qr: null,
      ready: isClientReady,
      authenticated: isAuthenticated,
      timestamp: new Date().toISOString()
    });
  }
  
  // If session exists but client is not ready, it's authenticating (no QR will be generated)
  if (hasSession) {
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
    // Initialize client if not already initialized (will generate QR since no session)
    if (!clientInitialized && !isManualDisconnect) {
      initializeClientIfNeeded();
    }
  }
  
  // Return current QR status
  res.status(200).json({ 
    qr: currentQR || null,
    ready: isClientReady,
    authenticated: isAuthenticated,
    timestamp: new Date().toISOString()
  });
});

registerRoute("post", "/api/disconnect", requireAuth, async (req, res) => {
  try {
    // Step 1: Set flags to prevent auto-reconnect
    isManualDisconnect = true;
    clientInitialized = false;
    
    // Step 2: Clear all state IMMEDIATELY
    currentQR = null;
    isAuthenticated = false;
    isClientReady = false;
    reconnectAttempts = 0;
    
    // Step 3: Notify all SSE clients IMMEDIATELY
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
    
    // Step 4: Send immediate status update
    const statusMessage = JSON.stringify({
      type: 'status',
      data: {
        authenticated: false,
        ready: false,
        hasQR: false,
        timestamp: new Date().toISOString()
      }
    });
    sseClients.forEach(client => {
      try {
        client.write(`data: ${statusMessage}\n\n`);
      } catch (err) {
        sseClients.delete(client);
      }
    });
    
    // Step 5: Destroy the client immediately
    try {
      await client.destroy();
    } catch (err) {
      // Ignore destroy errors - client may already be destroyed
    }
    clientInitialized = false;
    
    // Step 6: Aggressively delete session directory with multiple attempts
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
            break;
          }
        } else {
          break;
        }
      } catch (err) {
        await new Promise(resolve => setTimeout(resolve, 200));
      }
    }
    
    // Step 7: Delete entire auth directory and recreate it fresh
    try {
      if (fs.existsSync(AUTH_DIR)) {
        fs.rmSync(AUTH_DIR, { recursive: true, force: true });
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      if (!fs.existsSync(AUTH_DIR)) {
        fs.mkdirSync(AUTH_DIR, { recursive: true });
      }
    } catch (err) {
      // Ignore errors - directory will be recreated on next init
    }
    
    // Step 8: Reset manual disconnect flag for next reconnect
    isManualDisconnect = false;
    
    res.json({ 
      success: true, 
      message: "Completely disconnected. Click 'Reconnect' to generate a new QR code.",
      wiped: true
    });
    
  } catch (err) {
    isManualDisconnect = false;
    clientInitialized = false;
    res.status(500).json({ success: false, message: err.message });
  }
});

// Reconnect endpoint - manually initialize client to generate new QR code
registerRoute("post", "/api/reconnect", requireAuth, async (req, res) => {
  try {
    // Step 1: Reset flags
    isManualDisconnect = false;
    reconnectAttempts = 0;
    clientInitialized = false;
    
    // Step 2: Clear state
    currentQR = null;
    isAuthenticated = false;
    isClientReady = false;
    
    // Step 3: Destroy old client completely
    try {
      await client.destroy();
      clientInitialized = false;
      await new Promise(resolve => setTimeout(resolve, 1000));
    } catch (err) {
      clientInitialized = false;
    }
    
    // Step 4: Ensure auth directory is completely clean
    const sessionPath = path.join(AUTH_DIR, "session-default");
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        if (fs.existsSync(sessionPath)) {
          fs.rmSync(sessionPath, { recursive: true, force: true, maxRetries: 5 });
          await new Promise(resolve => setTimeout(resolve, 100));
        }
      } catch (err) {
        await new Promise(resolve => setTimeout(resolve, 200));
      }
    }
    
    // Step 5: Ensure auth directory exists for fresh start
    try {
      if (!fs.existsSync(AUTH_DIR)) {
        fs.mkdirSync(AUTH_DIR, { recursive: true });
      }
    } catch (err) {
      // Ignore
    }
    
    // Step 6: Initialize fresh client to generate QR
    client.initialize().then(() => {
      clientInitialized = true;
    }).catch(err => {
      clientInitialized = false;
    });
    
    // Step 7: Wait for QR code to be generated
    let qrGenerated = false;
    for (let i = 0; i < 30; i++) { // Wait up to 15 seconds
      await new Promise(resolve => setTimeout(resolve, 500));
      if (currentQR) {
        qrGenerated = true;
        break;
      }
    }
    
    if (qrGenerated) {
      res.json({ 
        success: true, 
        message: "Reconnected! QR code is ready.", 
        qr: currentQR,
        fresh: true 
      });
    } else {
      res.json({ 
        success: true, 
        message: "Reconnecting... QR code will appear shortly.",
        fresh: true 
      });
    }
  } catch (err) {
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

// Serve static files from public directory (must be last, after all API routes)
app.use(express.static(path.join(__dirname, "public")));

// Initialize client on server start ONLY if not manually disconnected
let clientInitialized = false;

function initializeClientIfNeeded() {
  if (clientInitialized || isManualDisconnect) {
    return;
  }
  
  const sessionPath = path.join(AUTH_DIR, "session-default");

  client.initialize().then(() => {
    clientInitialized = true;
  }).catch(err => {
    clientInitialized = false;
  });
}

// Initialize on server start (only if not manually disconnected)
if (!isManualDisconnect) {
  initializeClientIfNeeded();
}

app.listen(port, "0.0.0.0", () => {
  // Server started
});

process.on("SIGINT", async () => {
  await client.destroy();
  process.exit(0);
});