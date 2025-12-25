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

// ==================== EXPRESS SETUP ====================
const app = express();

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(cookieParser());

// Security headers
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  next();
});

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
          console.error(`[ERROR] ${method.toUpperCase()} ${route}:`, error.message);
          res.status(500).json({
            error: error.message || "Internal server error"
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
const puppeteerConfig = {
  headless: true,
  args: [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--mute-audio",
    "--disable-extensions",
    "--disable-plugins"
  ]
};

if (chromiumPath) {
  puppeteerConfig.executablePath = chromiumPath;
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

const setupClientEventHandlers = () => {
  const client = appState.client;

  // QR Event
  client.on("qr", qr => {
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
  });

  // Authenticated Event
  client.on("authenticated", () => {
    logger.success("EVENT", "AUTHENTICATED");
    appState.isAuthenticated = true;
    broadcastSSE({ type: "qr_scanned", message: "QR Scanned Successfully" });
  });

  // Ready Event
  client.on("ready", () => {
    logger.success("EVENT", "CLIENT READY");
    appState.isClientReady = true;
    appState.isAuthenticated = true;
    appState.currentQR = null;
    broadcastSSE({ type: "ready", message: "Client Ready for Messages" });
  });

  // Disconnected Event
  client.on("disconnected", reason => {
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
  });

  // Auth Failure Event
  client.on("auth_failure", msg => {
    logger.error("EVENT", `Auth failure: ${msg}`);
    appState.isAuthenticated = false;
    appState.isClientReady = false;
    appState.qrEventFired = false;
    broadcastSSE({
      type: "auth_failure",
      message: "Authentication Failed"
    });
  });

  // Message Event (optional - for monitoring)
  client.on("message", message => {
    logger.info("MESSAGE", `From ${message.from}: ${message.body.substring(0, 50)}`);
  });
};

// ==================== SSE BROADCAST ====================
const broadcastSSE = data => {
  const payload = `data: ${JSON.stringify(data)}\n\n`;
  const deadClients = [];

  sseClients.forEach(res => {
    try {
      res.write(payload);
    } catch (err) {
      logger.warn("SSE", `Failed to write to client: ${err.message}`);
      deadClients.push(res);
    }
  });

  deadClients.forEach(res => sseClients.delete(res));
};

// ==================== AUTHENTICATION ROUTES ====================
registerRoute("post", "/api/login", (req, res) => {
  const { email, password } = req.body;

  if (!LOGIN_PASSWORD) {
    return res.status(500).json({ error: "Login not configured" });
  }

  if (email === LOGIN_EMAIL && password === LOGIN_PASSWORD) {
    const sessionId = crypto.randomBytes(32).toString("hex");
    sessions.add(sessionId);

    res.cookie("sessionId", sessionId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: SESSION_MAX_AGE
    });

    logger.success("AUTH", `User logged in: ${email}`);
    res.json({ success: true });
  } else {
    logger.warn("AUTH", "Failed login attempt");
    res.status(401).json({ error: "Invalid credentials" });
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
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");

  res.write(`data: ${JSON.stringify({ type: "connected" })}\n\n`);
  sseClients.add(res);

  const status = {
    type: "status",
    data: {
      authenticated: appState.isAuthenticated,
      ready: appState.isClientReady,
      hasQR: appState.currentQR !== null
    }
  };
  res.write(`data: ${JSON.stringify(status)}\n\n`);

  const cleanupClient = () => {
    sseClients.delete(res);
    clearInterval(heartbeat);
  };

  req.on("close", cleanupClient);

  const heartbeat = setInterval(() => {
    try {
      res.write(": heartbeat\n\n");
    } catch (err) {
      cleanupClient();
    }
  }, SSE_HEARTBEAT_INTERVAL);
});

// ==================== STATUS ENDPOINT ====================
registerRoute("get", "/status", (req, res) => {
  appState.lastStatusCheck = new Date();

  res.json({
    authenticated: appState.isAuthenticated,
    ready: appState.isClientReady,
    hasQR: appState.currentQR !== null,
    qrEventFired: appState.qrEventFired,
    clientId: appState.clientId,
    manuallyDisconnected: appState.isManuallyDisconnected,
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage(),
    timestamp: new Date().toISOString()
  });
});

// ==================== QR ENDPOINT ====================
registerRoute("get", "/api/qr", requireAuth, async (req, res) => {
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
    } catch (err) {
      logger.error("QR", `Init error: ${err.message}`);
    }

    // Wait for QR event
    logger.info("QR", "Waiting for QR event (max 25 seconds)...");
    const startTime = Date.now();
    let lastLogTime = startTime;

    while (Date.now() - startTime < QR_TIMEOUT) {
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

      // Already authenticated
      if (appState.isClientReady) {
        logger.success("QR", "Already ready (authenticated from saved session)");
        return res.json({
          qr: null,
          ready: true,
          authenticated: true,
          message: "Already authenticated"
        });
      }

      // Log status every 5 seconds
      const now = Date.now();
      if (now - lastLogTime >= STATUS_LOG_INTERVAL) {
        logger.info("QR", `Waiting... (${Math.round((now - startTime) / 1000)}s elapsed)`);
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
  let num = phone.toString().trim().replace(/[^0-9]/g, "");
  if (num.startsWith("0")) num = "963" + num.substring(1);
  if (num.length < 10) num = "963" + num;
  return num;
};

const getChatId = async phoneNumber => {
  try {
    const formatted = formatPhone(phoneNumber);
    const numberId = await appState.client.getNumberId(formatted);
    return numberId ? numberId._serialized : formatted + "@c.us";
  } catch (err) {
    logger.warn("MESSAGE", `Failed to get number ID for ${phoneNumber}`);
    return formatPhone(phoneNumber) + "@c.us";
  }
};

registerRoute("post", "/send-message", requireAuth, async (req, res) => {
  const { phoneNumber, message } = req.body;

  if (!phoneNumber || !message) {
    return res.status(400).json({
      success: false,
      message: "Missing phoneNumber or message"
    });
  }

  if (!appState.isClientReady) {
    return res.status(503).json({
      success: false,
      message: "Client not ready"
    });
  }

  try {
    const chatId = await getChatId(phoneNumber);
    await appState.client.sendMessage(chatId, message);

    logger.success("MESSAGE", `Sent to ${phoneNumber}`);

    res.json({
      success: true,
      message: "Message sent successfully"
    });
  } catch (err) {
    logger.error("MESSAGE", `Failed to send: ${err.message}`);

    res.status(500).json({
      success: false,
      message: err.message
    });
  }
});

registerRoute("post", "/send-otp", requireAuth, async (req, res) => {
  const { phoneNumber, otp } = req.body;

  if (!phoneNumber || !otp) {
    return res.status(400).json({
      success: false,
      message: "Missing phoneNumber or otp"
    });
  }

  if (!appState.isClientReady) {
    return res.status(503).json({
      success: false,
      message: "Client not ready"
    });
  }

  try {
    const msg = `رمز التحقق: ${otp}`;
    const chatId = await getChatId(phoneNumber);
    await appState.client.sendMessage(chatId, msg);

    logger.success("OTP", `OTP sent to ${phoneNumber}`);

    res.json({
      success: true,
      message: "OTP sent successfully"
    });
  } catch (err) {
    logger.error("OTP", `Failed to send: ${err.message}`);

    res.status(500).json({
      success: false,
      message: err.message
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