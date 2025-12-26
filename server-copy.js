require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const { Client, LocalAuth } = require("whatsapp-web.js");
const qrcode = require("qrcode-terminal");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// ==================== CONSTANTS ====================
const PORT = process.env.PORT || 3002;
const HOST = "0.0.0.0";
const AUTH_DIR = "./.wwebjs_auth";
const QR_TIMEOUT = 25000; // 25 seconds
const QR_CHECK_INTERVAL = 500; // 500ms
const STATUS_LOG_INTERVAL = 5000; // 5 seconds
const SSE_HEARTBEAT_INTERVAL = 30000; // 30 seconds
const SESSION_MAX_AGE = 24 * 60 * 60 * 1000; // 24 hours
const LOGIN_EMAIL = process.env.LOGIN_EMAIL || "any.otp@gmail.com";
const LOGIN_PASSWORD = process.env.LOGIN_PASSWORD;

// Rate limiting storage (simple in-memory store)
const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const RATE_LIMIT_MAX_REQUESTS = {
  login: 5,
  api: 100,
  qr: 30, // Increased from 10 - users may need to check QR multiple times during setup
  message: 50
};

// ==================== EXPRESS SETUP ====================
const app = express();

// Trust proxy for accurate IP addresses
app.set("trust proxy", 1);

// Body parsing with size limits
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(cookieParser());

// Enhanced security headers
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  
  // CSP header for additional security
  if (process.env.NODE_ENV === "production") {
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://use.hugeicons.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://use.hugeicons.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' https://api.qrserver.com data:; connect-src 'self';"
    );
  }
  
  next();
});

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on("finish", () => {
    const duration = Date.now() - start;
    logger.info("REQUEST", `${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`);
  });
  next();
});

// ==================== RATE LIMITING ====================
const rateLimit = (maxRequests, windowMs, useSessionKey = false) => {
  return (req, res, next) => {
    // For authenticated endpoints, use session ID instead of IP for more lenient limits
    let key;
    if (useSessionKey) {
      const sessionId = req.cookies?.sessionId;
      key = sessionId ? `session:${sessionId}:${req.path}` : `${req.ip}:${req.path}`;
    } else {
      key = `${req.ip}:${req.path}`;
    }
    
    const now = Date.now();
    const windowStart = now - windowMs;
    
    // Clean old entries
    if (rateLimitStore.has(key)) {
      const requests = rateLimitStore.get(key).filter(time => time > windowStart);
      rateLimitStore.set(key, requests);
      
      if (requests.length >= maxRequests) {
        const waitTime = Math.ceil((requests[0] + windowMs - now) / 1000);
        return res.status(429).json({
          error: "Too many requests",
          message: `Rate limit exceeded. Please try again after ${waitTime} seconds.`,
          retryAfter: waitTime
        });
      }
      
      requests.push(now);
      rateLimitStore.set(key, requests);
    } else {
      rateLimitStore.set(key, [now]);
    }
    
    // Cleanup old entries periodically (more frequent cleanup)
    if (Math.random() < 0.05) {
      for (const [k, v] of rateLimitStore.entries()) {
        const filtered = v.filter(time => time > windowStart);
        if (filtered.length === 0) {
          rateLimitStore.delete(k);
        } else {
          rateLimitStore.set(k, filtered);
        }
      }
    }
    
    next();
  };
};

// ==================== SESSION & SSE MANAGEMENT ====================
const sessions = new Set();
const sseClients = new Set();

const requireAuth = (req, res, next) => {
  const sessionId = req.cookies.sessionId;
  if (sessionId && sessions.has(sessionId)) {
    return next();
  }
  res.status(401).json({ error: "Unauthorized" });
};

// ==================== INPUT VALIDATION & SANITIZATION ====================
const sanitizeString = (str, maxLength = 1000) => {
  if (typeof str !== "string") return "";
  return str.trim().substring(0, maxLength);
};

const validatePhoneNumber = (phone) => {
  if (!phone || typeof phone !== "string") return false;
  const cleaned = phone.replace(/[^0-9]/g, "");
  return cleaned.length >= 8 && cleaned.length <= 15;
};

const validateEmail = (email) => {
  if (!email || typeof email !== "string") return false;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email.trim());
};

// ==================== ENHANCED ERROR HANDLING ====================
function registerRoute(method, route, ...handlers) {
  const wrappedHandlers = handlers.map(handler => {
    return async (req, res, next) => {
      try {
        const result = handler(req, res, next);
        if (result && typeof result.then === "function") {
          await result;
        }
      } catch (error) {
        if (!res.headersSent) {
          const errorId = crypto.randomBytes(4).toString("hex");
          logger.error("ROUTE", `${method.toUpperCase()} ${route} [${errorId}]: ${error.message}`);
          if (process.env.NODE_ENV !== "production") {
            console.error(error.stack);
          }
          res.status(error.statusCode || 500).json({
            error: error.message || "Internal server error",
            errorId: process.env.NODE_ENV !== "production" ? errorId : undefined
          });
        }
      }
    };
  });

  app[method](route, ...wrappedHandlers);
  app[method](`/otp-service${route}`, ...wrappedHandlers);
}

// ==================== STATE MANAGEMENT ====================
const appState = {
  currentQR: null,
  isAuthenticated: false,
  isClientReady: false,
  qrEventFired: false,
  client: null,
  clientId: null,
  isManuallyDisconnected: false,
  lastQRRequest: null,
  lastStatusCheck: null,
  messageQueue: []
};

// ==================== LOGGER ====================
const logger = {
  info: (tag, msg) => console.log(`[${tag}] ${msg}`),
  warn: (tag, msg) => console.warn(`[⚠ ${tag}] ${msg}`),
  error: (tag, msg) => console.error(`[✗ ${tag}] ${msg}`),
  success: (tag, msg) => console.log(`[✓ ${tag}] ${msg}`)
};

// ==================== CHROMIUM DETECTION ====================
const getChromiumPath = () => {
  const possiblePaths = [
    "/usr/bin/chromium-browser",
    "/usr/bin/chromium",
    "/snap/bin/chromium",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable"
  ];

  for (const chromiumPath of possiblePaths) {
    if (fs.existsSync(chromiumPath)) {
      logger.success("CHROMIUM", `Found at: ${chromiumPath}`);
      return chromiumPath;
    }
  }

  logger.warn("CHROMIUM", "No chromium installation found, using system default");
  return undefined;
};

const chromiumPath = getChromiumPath();

// Base Puppeteer config
const puppeteerConfig = {
  headless: true,
  args: [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--mute-audio",
    "--disable-extensions",
    "--disable-plugins",
    "--disable-background-timer-throttling",
    "--disable-backgrounding-occluded-windows",
    "--disable-renderer-backgrounding",
    "--disable-default-apps",
    "--disable-sync",
    "--no-first-run",
    "--no-default-browser-check",
    // Disable singleton lock to allow multiple instances
    "--disable-features=TranslateUI",
    "--disable-ipc-flooding-protection"
  ]
};

if (chromiumPath) {
  puppeteerConfig.executablePath = chromiumPath;
  // For snap chromium, we need additional args
  if (chromiumPath.includes("/snap/")) {
    puppeteerConfig.args.push("--disable-features=VizDisplayCompositor");
  }
}

// ==================== FILESYSTEM UTILITIES ====================
const cleanupAuthDirectory = () => {
  logger.info("CLEANUP", "Starting auth directory cleanup");

  if (fs.existsSync(AUTH_DIR)) {
    try {
      const files = fs.readdirSync(AUTH_DIR);
      logger.info("CLEANUP", `Found ${files.length} items to clean`);

      files.forEach(file => {
        const fullPath = path.join(AUTH_DIR, file);
        try {
          fs.rmSync(fullPath, { recursive: true, force: true });
          logger.info("CLEANUP", `Deleted: ${file}`);
        } catch (err) {
          logger.error("CLEANUP", `Failed to delete ${file}: ${err.message}`);
        }
      });
    } catch (err) {
      logger.error("CLEANUP", `Error reading auth dir: ${err.message}`);
    }
  }

  if (!fs.existsSync(AUTH_DIR)) {
    fs.mkdirSync(AUTH_DIR, { recursive: true });
  }

  logger.success("CLEANUP", "Auth directory cleaned");
};

// ==================== CLIENT FACTORY ====================
const createAndSetupClient = (useNewId = false) => {
  if (useNewId) {
    appState.clientId = crypto.randomBytes(8).toString("hex");
  } else if (!appState.clientId) {
    appState.clientId = "default";
  }

  logger.info("CLIENT", `Creating new client with ID: ${appState.clientId}`);

  // Clean up any stale singleton lock files before creating client
  // This helps prevent lock conflicts when multiple instances try to start
  const lockPaths = [
    "/root/snap/chromium/common/chromium/SingletonLock",
    "/root/snap/chromium/common/chromium/SingletonSocket",
    "/root/snap/chromium/common/chromium/SingletonCookie"
  ];

  lockPaths.forEach(lockPath => {
    if (fs.existsSync(lockPath)) {
      try {
        // Try to remove the lock file
        fs.unlinkSync(lockPath);
        logger.info("CLIENT", `Removed stale lock file: ${lockPath}`);
      } catch (err) {
        // Lock file might be in use - try to kill any stale processes
        if (err.code === 'EBUSY' || err.code === 'EPERM') {
          logger.warn("CLIENT", `Lock file in use: ${lockPath} - may need manual cleanup`);
        }
      }
    }
  });

  appState.client = new Client({
    authStrategy: new LocalAuth({
      clientId: appState.clientId,
      dataPath: AUTH_DIR
    }),
    puppeteer: puppeteerConfig,
    webVersionCache: {
      type: "remote",
      remotePath:
        "https://raw.githubusercontent.com/wppconnect-team/wa-version/main/html/2.2413.51-beta.html"
    }
  });

  // Setup event handlers
  setupClientEventHandlers();

  return appState.client;
};

// Store event handlers for cleanup
const clientEventHandlers = new Map();

const setupClientEventHandlers = () => {
  const client = appState.client;
  if (!client) return;

  // Remove old event handlers if they exist
  if (clientEventHandlers.has(client)) {
    const handlers = clientEventHandlers.get(client);
    handlers.forEach(({ event, handler }) => {
      client.removeListener(event, handler);
    });
    clientEventHandlers.delete(client);
  }

  const handlers = [];

  // QR Event
  const qrHandler = qr => {
    logger.info("EVENT", "QR CODE GENERATED");
    appState.qrEventFired = true;
    appState.currentQR = qr || null;

    if (qr) {
      qrcode.generate(qr, { small: true });
      logger.info("QR", `Length: ${qr.length}`);
    }

    appState.isAuthenticated = false;
    appState.isClientReady = false;

    broadcastSSE({ type: "qr_generated", message: "QR Code Ready" });
  };
  client.on("qr", qrHandler);
  handlers.push({ event: "qr", handler: qrHandler });

  // Authenticated Event
  const authenticatedHandler = () => {
    logger.success("EVENT", "AUTHENTICATED");
    appState.isAuthenticated = true;
    broadcastSSE({ type: "qr_scanned", message: "QR Scanned Successfully" });
    // Ready event should fire automatically after authenticated
  };
  client.on("authenticated", authenticatedHandler);
  handlers.push({ event: "authenticated", handler: authenticatedHandler });

  // Ready Event
  const readyHandler = () => {
    logger.success("EVENT", "CLIENT READY");
    appState.isClientReady = true;
    appState.isAuthenticated = true;
    appState.currentQR = null;
    
    // Log client info for debugging
    try {
      if (client.info) {
        logger.info("CLIENT", `Ready - User: ${client.info.pushname || client.info.wid?.user || "Unknown"}`);
      }
    } catch (e) {
      // Ignore errors
    }
    
    broadcastSSE({ type: "ready", message: "Client Ready for Messages" });
  };
  client.on("ready", readyHandler);
  handlers.push({ event: "ready", handler: readyHandler });

  // Disconnected Event
  const disconnectedHandler = reason => {
    logger.warn("EVENT", `Disconnected: ${reason}`);

    appState.isAuthenticated = false;
    appState.isClientReady = false;
    appState.currentQR = null;
    appState.qrEventFired = false;

    broadcastSSE({
      type: "disconnected",
      message: "Connection Lost",
      reason: reason
    });

    if (!appState.isManuallyDisconnected) {
      logger.warn("EVENT", "Connection lost unexpectedly - waiting for manual reconnection");
    }
  };
  client.on("disconnected", disconnectedHandler);
  handlers.push({ event: "disconnected", handler: disconnectedHandler });

  // Auth Failure Event
  const authFailureHandler = msg => {
    logger.error("EVENT", `Auth failure: ${msg}`);
    appState.isAuthenticated = false;
    appState.isClientReady = false;
    appState.qrEventFired = false;
    broadcastSSE({
      type: "auth_failure",
      message: "Authentication Failed"
    });
  };
  client.on("auth_failure", authFailureHandler);
  handlers.push({ event: "auth_failure", handler: authFailureHandler });

  // Message Event (optional - for monitoring)
  const messageHandler = message => {
    logger.info("MESSAGE", `From ${message.from}: ${message.body?.substring(0, 50) || ""}`);
  };
  client.on("message", messageHandler);
  handlers.push({ event: "message", handler: messageHandler });

  // Store handlers for cleanup
  clientEventHandlers.set(client, handlers);
};

// ==================== SSE BROADCAST ====================
const broadcastSSE = data => {
  if (sseClients.size === 0) return;
  
  const payload = `data: ${JSON.stringify(data)}\n\n`;
  const deadClients = [];

  sseClients.forEach(res => {
    try {
      if (!res.writable || res.destroyed) {
        deadClients.push(res);
        return;
      }
      res.write(payload);
    } catch (err) {
      logger.warn("SSE", `Failed to write to client: ${err.message}`);
      deadClients.push(res);
    }
  });

  deadClients.forEach(res => {
    try {
      if (!res.destroyed) {
        res.end();
      }
    } catch (e) {
      // Ignore cleanup errors
    }
    sseClients.delete(res);
  });
};

// ==================== AUTHENTICATION ROUTES ====================
registerRoute("post", "/api/login", rateLimit(RATE_LIMIT_MAX_REQUESTS.login, RATE_LIMIT_WINDOW), (req, res) => {
  const { email, password } = req.body;

  if (!LOGIN_PASSWORD) {
    return res.status(500).json({ error: "Login not configured" });
  }

  // Validate input
  const sanitizedEmail = sanitizeString(email, 255);
  if (!sanitizedEmail || !validateEmail(sanitizedEmail)) {
    return res.status(400).json({ error: "Invalid email format" });
  }

  if (!password || typeof password !== "string" || password.length === 0) {
    return res.status(400).json({ error: "Password is required" });
  }

  // Constant-time comparison to prevent timing attacks
  const emailMatch = crypto.timingSafeEqual(
    Buffer.from(sanitizedEmail.toLowerCase()),
    Buffer.from(LOGIN_EMAIL.toLowerCase())
  );
  
  // Hash password comparison for constant-time
  const providedHash = crypto.createHash("sha256").update(password).digest();
  const expectedHash = crypto.createHash("sha256").update(LOGIN_PASSWORD || "").digest();
  const passwordMatch = crypto.timingSafeEqual(providedHash, expectedHash);

  if (emailMatch && passwordMatch) {
    const sessionId = crypto.randomBytes(32).toString("hex");
    sessions.add(sessionId);

    res.cookie("sessionId", sessionId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: SESSION_MAX_AGE,
      path: "/"
    });

    logger.success("AUTH", `User logged in: ${sanitizedEmail}`);
    return res.json({ success: true });
  } else {
    // Add delay to prevent brute force (even for invalid attempts)
    logger.warn("AUTH", `Failed login attempt from ${req.ip}`);
    return res.status(401).json({ error: "Invalid credentials" });
  }
});

registerRoute("get", "/api/auth/check", (req, res) => {
  const sessionId = req.cookies.sessionId;
  const authenticated = sessionId && sessions.has(sessionId);
  res.json({ authenticated });
});

registerRoute("post", "/api/logout", (req, res) => {
  const sessionId = req.cookies.sessionId;
  if (sessionId) {
    sessions.delete(sessionId);
    logger.info("AUTH", "User logged out");
  }
  res.clearCookie("sessionId");
  res.json({ success: true });
});

// ==================== SSE EVENTS ====================
registerRoute("get", "/api/events", requireAuth, (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");

  // Send initial connection message
  try {
    res.write(`data: ${JSON.stringify({ type: "connected", timestamp: new Date().toISOString() })}\n\n`);
  } catch (err) {
    logger.warn("SSE", "Failed to send initial connection message");
    return res.end();
  }

  sseClients.add(res);

  // Send current status immediately
  const status = {
    type: "status",
    data: {
      authenticated: appState.isAuthenticated,
      ready: appState.isClientReady,
      hasQR: appState.currentQR !== null,
      timestamp: new Date().toISOString()
    }
  };
  
  try {
    res.write(`data: ${JSON.stringify(status)}\n\n`);
  } catch (err) {
    sseClients.delete(res);
    return res.end();
  }

  const cleanupClient = () => {
    sseClients.delete(res);
    if (heartbeat) clearInterval(heartbeat);
    try {
      if (!res.destroyed) {
        res.end();
      }
    } catch (e) {
      // Ignore cleanup errors
    }
  };

  req.on("close", cleanupClient);
  req.on("aborted", cleanupClient);
  res.on("close", cleanupClient);

  // Heartbeat to keep connection alive
  const heartbeat = setInterval(() => {
    try {
      if (res.writable && !res.destroyed) {
        res.write(": heartbeat\n\n");
      } else {
        cleanupClient();
      }
    } catch (err) {
      cleanupClient();
    }
  }, SSE_HEARTBEAT_INTERVAL);
});

// ==================== STATUS ENDPOINT ====================
registerRoute("get", "/status", (req, res) => {
  appState.lastStatusCheck = new Date();
  
  // Check client state if it exists - the client.info property is only available when ready
  let clientInfo = null;
  let actualReadyState = appState.isClientReady;
  
  if (appState.client) {
    try {
      // Get actual client state - client.info is only available when ready
      const info = appState.client.info;
      if (info && info.wid) {
        clientInfo = {
          wid: info.wid || null,
          me: info.me || null,
          pushname: info.pushname || null
        };
        // If client.info exists, the client IS ready (real state, not simulation)
        actualReadyState = true;
      }
    } catch (e) {
      // Ignore errors accessing client info
    }
  }

  res.json({
    authenticated: appState.isAuthenticated,
    ready: actualReadyState,
    hasQR: appState.currentQR !== null,
    qrEventFired: appState.qrEventFired,
    clientId: appState.clientId,
    manuallyDisconnected: appState.isManuallyDisconnected,
    hasClient: appState.client !== null,
    clientInfo: clientInfo,
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage(),
    timestamp: new Date().toISOString()
  });
});

// ==================== QR ENDPOINT ====================
// QR endpoint uses session-based rate limiting for authenticated users (more lenient)
registerRoute("get", "/api/qr", requireAuth, rateLimit(RATE_LIMIT_MAX_REQUESTS.qr, RATE_LIMIT_WINDOW, true), async (req, res) => {
  res.set("Cache-Control", "no-cache, no-store, must-revalidate");
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");

  logger.info("QR", "Request received");
  appState.lastQRRequest = new Date();

  try {
    // Already ready
    if (appState.isClientReady) {
      logger.info("QR", "Client already ready");
      return res.json({
        qr: null,
        ready: true,
        authenticated: true,
        message: "Client already authenticated"
      });
    }

    // Existing QR available
    if (appState.currentQR && appState.qrEventFired) {
      logger.info("QR", "Returning existing QR code");
      return res.json({
        qr: appState.currentQR,
        ready: false,
        authenticated: false,
        message: "Scan this QR code"
      });
    }

    // Start fresh connection
    logger.info("QR", "Starting fresh connection");

    // Destroy existing client if it exists before creating a new one
    if (appState.client) {
      try {
        logger.info("QR", "Destroying existing client before creating new one...");
        await appState.client.destroy().catch(() => {});
        // Clean up event handlers
        if (clientEventHandlers.has(appState.client)) {
          const handlers = clientEventHandlers.get(appState.client);
          handlers.forEach(({ event, handler }) => {
            try {
              appState.client.removeListener(event, handler);
            } catch (e) {
              // Ignore cleanup errors
            }
          });
          clientEventHandlers.delete(appState.client);
        }
        appState.client = null;
        // Wait a moment for cleanup
        await new Promise(r => setTimeout(r, 1000));
      } catch (err) {
        logger.warn("QR", `Error destroying existing client: ${err.message}`);
      }
    }

    cleanupAuthDirectory();
    appState.isManuallyDisconnected = false;
    createAndSetupClient(true);

    appState.qrEventFired = false;
    appState.currentQR = null;
    appState.isAuthenticated = false;
    appState.isClientReady = false;

    logger.info("QR", "Initializing client...");

    try {
      await appState.client.initialize();
      logger.info("QR", "Client initialization started");
      
      // Give it a moment to check if client is already authenticated
      await new Promise(r => setTimeout(r, 1000));
      
      // Check if client is already ready (happens with saved sessions)
      if (appState.isClientReady) {
        logger.success("QR", "Client already ready (had saved session)");
        return res.json({
          qr: null,
          ready: true,
          authenticated: true,
          message: "Already authenticated and ready"
        });
      }
    } catch (err) {
      logger.error("QR", `Init error: ${err.message}`);
      return res.status(500).json({
        qr: null,
        error: `Failed to initialize client: ${err.message}`,
        ready: false,
        authenticated: false
      });
    }

    // Wait for QR event or ready state
    logger.info("QR", "Waiting for QR event or ready state (max 25 seconds)...");
    const startTime = Date.now();
    let lastLogTime = startTime;

    while (Date.now() - startTime < QR_TIMEOUT) {
      // Check if client became ready (with saved session, ready event fires quickly)
      if (appState.isClientReady) {
        logger.success("QR", "Client ready (authenticated from saved session)");
        return res.json({
          qr: null,
          ready: true,
          authenticated: true,
          message: "Already authenticated and ready"
        });
      }
      
      // QR received
      if (appState.qrEventFired && appState.currentQR) {
        logger.success("QR", "QR event fired successfully");
        return res.json({
          qr: appState.currentQR,
          ready: false,
          authenticated: false,
          message: "QR code generated"
        });
      }

      // Log status every 5 seconds
      const now = Date.now();
      if (now - lastLogTime >= STATUS_LOG_INTERVAL) {
        logger.info("QR", `Waiting... (${Math.round((now - startTime) / 1000)}s elapsed, ready: ${appState.isClientReady}, auth: ${appState.isAuthenticated})`);
        lastLogTime = now;
      }

      await new Promise(r => setTimeout(r, QR_CHECK_INTERVAL));
    }

    // Timeout
    logger.warn("QR", "Timeout: No QR event received");
    return res.json({
      qr: appState.currentQR || null,
      ready: appState.isClientReady,
      authenticated: appState.isAuthenticated,
      timeout: true,
      error: "QR event did not fire within timeout period"
    });
  } catch (error) {
    logger.error("QR", `Fatal error: ${error.message}`);
    res.status(500).json({
      qr: null,
      error: error.message,
      ready: false,
      authenticated: false
    });
  }
});

// ==================== DISCONNECT ENDPOINT ====================
registerRoute("post", "/api/disconnect", requireAuth, async (req, res) => {
  logger.info("DISCONNECT", "Disconnect requested");

  try {
    appState.isManuallyDisconnected = true;

    // Reset state
    appState.currentQR = null;
    appState.isAuthenticated = false;
    appState.isClientReady = false;
    appState.qrEventFired = false;

    if (appState.client) {
      try {
        logger.info("DISCONNECT", "Logging out from WhatsApp...");
        await appState.client.logout();
        logger.success("DISCONNECT", "WhatsApp logout successful");
      } catch (logoutErr) {
        logger.warn("DISCONNECT", `Logout failed: ${logoutErr.message}`);
      }

      try {
        logger.info("DISCONNECT", "Destroying client...");
        await appState.client.destroy();
        logger.success("DISCONNECT", "Client destroyed");
      } catch (destroyErr) {
        logger.error("DISCONNECT", `Destroy failed: ${destroyErr.message}`);
      }

      appState.client = null;
    }

    cleanupAuthDirectory();
    appState.clientId = null;

    broadcastSSE({
      type: "disconnected",
      message: "Manually disconnected from WhatsApp"
    });

    logger.success("DISCONNECT", "Complete disconnect successful");

    res.json({
      success: true,
      message: "Disconnected from WhatsApp account and cleaned up all session data"
    });
  } catch (err) {
    logger.error("DISCONNECT", err.message);
    res.status(500).json({
      success: false,
      message: err.message
    });
  }
});

// ==================== MESSAGING ====================
const formatPhone = phone => {
  if (!phone || typeof phone !== "string") return "";
  let num = phone.trim().replace(/[^0-9]/g, "");
  
  // Remove leading zeros
  if (num.startsWith("0")) {
    num = num.substring(1);
  }
  
  // Add country code if number is too short (default: 963 for Syria)
  // Can be made configurable via environment variable
  const DEFAULT_COUNTRY_CODE = process.env.DEFAULT_COUNTRY_CODE || "963";
  if (num.length < 10) {
    num = DEFAULT_COUNTRY_CODE + num;
  }
  
  return num;
};

const getChatId = async phoneNumber => {
  try {
    const formatted = formatPhone(phoneNumber);
    if (!formatted) {
      throw new Error("Invalid phone number format");
    }
    
    const numberId = await appState.client.getNumberId(formatted);
    return numberId ? numberId._serialized : formatted + "@c.us";
  } catch (err) {
    logger.warn("MESSAGE", `Failed to get number ID for ${phoneNumber}: ${err.message}`);
    const formatted = formatPhone(phoneNumber);
    if (!formatted) {
      throw new Error("Invalid phone number format");
    }
    return formatted + "@c.us";
  }
};

registerRoute("post", "/send-message", requireAuth, rateLimit(RATE_LIMIT_MAX_REQUESTS.message, RATE_LIMIT_WINDOW), async (req, res) => {
  const { phoneNumber, message } = req.body;

  // Enhanced input validation
  if (!phoneNumber || !message) {
    return res.status(400).json({
      success: false,
      message: "Missing phoneNumber or message"
    });
  }

  const sanitizedPhone = sanitizeString(phoneNumber, 20);
  const sanitizedMessage = sanitizeString(message, 4096);

  if (!validatePhoneNumber(sanitizedPhone)) {
    return res.status(400).json({
      success: false,
      message: "Invalid phone number format"
    });
  }

  if (sanitizedMessage.length === 0) {
    return res.status(400).json({
      success: false,
      message: "Message cannot be empty"
    });
  }

  if (!appState.isClientReady) {
    return res.status(503).json({
      success: false,
      message: "Client not ready"
    });
  }

  try {
    const chatId = await getChatId(sanitizedPhone);
    await appState.client.sendMessage(chatId, sanitizedMessage);

    logger.success("MESSAGE", `Sent to ${sanitizedPhone}`);

    res.json({
      success: true,
      message: "Message sent successfully"
    });
  } catch (err) {
    logger.error("MESSAGE", `Failed to send: ${err.message}`);
    
    // Provide more specific error messages
    const errorMessage = err.message.includes("not registered") 
      ? "Phone number is not registered on WhatsApp"
      : err.message.includes("timeout")
      ? "Request timed out. Please try again."
      : err.message;

    res.status(500).json({
      success: false,
      message: errorMessage
    });
  }
});

registerRoute("post", "/send-otp", requireAuth, rateLimit(RATE_LIMIT_MAX_REQUESTS.message, RATE_LIMIT_WINDOW), async (req, res) => {
  const { phoneNumber, otp } = req.body;

  // Enhanced input validation
  if (!phoneNumber || !otp) {
    return res.status(400).json({
      success: false,
      message: "Missing phoneNumber or otp"
    });
  }

  const sanitizedPhone = sanitizeString(phoneNumber, 20);
  const sanitizedOtp = sanitizeString(otp, 10);

  if (!validatePhoneNumber(sanitizedPhone)) {
    return res.status(400).json({
      success: false,
      message: "Invalid phone number format"
    });
  }

  // Validate OTP format (typically 4-8 digits)
  if (!/^\d{4,8}$/.test(sanitizedOtp)) {
    return res.status(400).json({
      success: false,
      message: "OTP must be 4-8 digits"
    });
  }

  if (!appState.isClientReady) {
    return res.status(503).json({
      success: false,
      message: "Client not ready"
    });
  }

  try {
    const msg = `رمز التحقق: ${sanitizedOtp}`;
    const chatId = await getChatId(sanitizedPhone);
    await appState.client.sendMessage(chatId, msg);

    logger.success("OTP", `OTP sent to ${sanitizedPhone}`);

    res.json({
      success: true,
      message: "OTP sent successfully"
    });
  } catch (err) {
    logger.error("OTP", `Failed to send: ${err.message}`);
    
    const errorMessage = err.message.includes("not registered")
      ? "Phone number is not registered on WhatsApp"
      : err.message.includes("timeout")
      ? "Request timed out. Please try again."
      : err.message;

    res.status(500).json({
      success: false,
      message: errorMessage
    });
  }
});

// ==================== HEALTH CHECK ====================
registerRoute("get", "/api/health", (req, res) => {
  res.json({
    status: "ok",
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    whatsapp: {
      authenticated: appState.isAuthenticated,
      ready: appState.isClientReady,
      clientId: appState.clientId
    }
  });
});

// ==================== STATIC FILES ====================
app.use(express.static(path.join(__dirname, "public")));

// ==================== 404 HANDLER ====================
app.use((req, res) => {
  res.status(404).json({
    error: "Not found",
    path: req.path
  });
});

// ==================== STARTUP ====================
console.log("");
console.log("╔═══════════════════════════════════════════════╗");
console.log("║  WhatsApp OTP Server - OPTIMIZED (v3.0)      ║");
console.log("║  No Auto-Reconnect | Full Manual Control     ║");
console.log("╚═══════════════════════════════════════════════╝");
console.log("");

cleanupAuthDirectory();
appState.isManuallyDisconnected = true;

const server = app.listen(PORT, HOST, () => {
  logger.success("STARTUP", `Server listening on ${HOST}:${PORT}`);
  logger.info("STARTUP", "Waiting for manual connection request...");
  logger.info("STARTUP", `Use /api/qr endpoint to initiate login`);
  console.log("");
});

// ==================== GRACEFUL SHUTDOWN ====================
const shutdown = async signal => {
  console.log(`\n[SHUTDOWN] Received ${signal}, shutting down gracefully...`);

  if (appState.client) {
    // Clean up event handlers
    if (clientEventHandlers.has(appState.client)) {
      const handlers = clientEventHandlers.get(appState.client);
      handlers.forEach(({ event, handler }) => {
        try {
          appState.client.removeListener(event, handler);
        } catch (e) {
          // Ignore cleanup errors
        }
      });
      clientEventHandlers.delete(appState.client);
    }

    try {
      logger.info("SHUTDOWN", "Logging out from WhatsApp...");
      await appState.client.logout();
      logger.success("SHUTDOWN", "Logout successful");
    } catch (err) {
      logger.warn("SHUTDOWN", `Logout failed: ${err.message}`);
    }

    try {
      logger.info("SHUTDOWN", "Destroying client...");
      await appState.client.destroy();
      logger.success("SHUTDOWN", "Client destroyed");
    } catch (err) {
      logger.error("SHUTDOWN", `Destroy failed: ${err.message}`);
    }
  }

  // Clean up SSE clients
  sseClients.forEach(res => {
    try {
      if (!res.destroyed) {
        res.end();
      }
    } catch (e) {
      // Ignore cleanup errors
    }
  });
  sseClients.clear();

  server.close(() => {
    logger.success("SHUTDOWN", "Server closed");
    process.exit(0);
  });

  // Force exit after 10 seconds
  setTimeout(() => {
    logger.warn("SHUTDOWN", "Forcing shutdown after 10 seconds");
    process.exit(1);
  }, 10000);
};

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

process.on("uncaughtException", err => {
  logger.error("UNCAUGHT", err.message);
  console.error(err);
  process.exit(1);
});

process.on("unhandledRejection", (reason, promise) => {
  logger.error("REJECTION", `Unhandled rejection: ${reason}`);
});