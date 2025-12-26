require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const { Client, LocalAuth } = require("whatsapp-web.js");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(cookieParser());

// Constants
const LOGIN_EMAIL = process.env.LOGIN_EMAIL;
const LOGIN_PASSWORD = process.env.LOGIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET || "default-secret-key";
const BASE_PATH = "/otp-service";

// In-memory state management
const state = {
  sessions: new Map(),
  clients: new Map(),
  qrCodes: new Map(),
  eventListeners: new Map(),
};

// ==================== SESSION MANAGEMENT ====================

function generateSessionId() {
  return require("crypto").randomBytes(32).toString("hex");
}

function createSession(email) {
  const sessionId = generateSessionId();
  const session = {
    email,
    createdAt: Date.now(),
    expiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24 hours
  };
  state.sessions.set(sessionId, session);
  return sessionId;
}

function validateSession(req) {
  const sessionId = req.cookies.sessionId;
  if (!sessionId) return null;

  const session = state.sessions.get(sessionId);
  if (!session || session.expiresAt < Date.now()) {
    state.sessions.delete(sessionId);
    return null;
  }

  return session;
}

function authenticate(req, res, next) {
  const session = validateSession(req);
  if (!session) {
    return res.status(401).json({ success: false, error: "Unauthorized" });
  }
  req.session = session;
  req.sessionId = req.cookies.sessionId;
  next();
}

// ==================== WHATSAPP CLIENT MANAGEMENT ====================

async function initializeWhatsAppClient(sessionId) {
  if (state.clients.has(sessionId)) {
    return state.clients.get(sessionId);
  }

  const sessionPath = path.join(process.cwd(), ".auth", sessionId);
  
  const client = new Client({
    authStrategy: new LocalAuth({ clientId: sessionId }),
    puppeteer: {
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH,
      args: ["--no-sandbox", "--disable-setuid-sandbox"],
    },
  });

  client.on("qr", (qr) => {
    state.qrCodes.set(sessionId, qr);
    broadcastToSession(sessionId, {
      type: "qr_generated",
      data: { hasQR: true },
    });
  });

  client.on("ready", () => {
    state.qrCodes.delete(sessionId);
    broadcastToSession(sessionId, { type: "ready" });
  });

  client.on("authenticated", () => {
    broadcastToSession(sessionId, { type: "qr_scanned" });
  });

  client.on("disconnected", () => {
    state.qrCodes.delete(sessionId);
    state.clients.delete(sessionId);
    broadcastToSession(sessionId, { type: "disconnected" });
  });

  client.on("error", (error) => {
    console.error(`[${sessionId}] Client error:`, error);
  });

  await client.initialize();
  state.clients.set(sessionId, client);
  return client;
}

function getClientStatus(sessionId) {
  const client = state.clients.get(sessionId);
  const hasQR = state.qrCodes.has(sessionId);

  return {
    ready: client ? client.info?.pushname !== undefined : false,
    authenticated: !!client,
    hasQR,
    timestamp: new Date().toISOString(),
  };
}

function broadcastToSession(sessionId, data) {
  const listeners = state.eventListeners.get(sessionId) || [];
  listeners.forEach((res) => {
    if (!res.writableEnded) {
      res.write(`data: ${JSON.stringify(data)}\n\n`);
    }
  });
  state.eventListeners.set(
    sessionId,
    listeners.filter((res) => !res.writableEnded)
  );
}

// ==================== ROUTES ====================

// Login
app.post(`${BASE_PATH}/api/login`, (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res
      .status(400)
      .json({ success: false, error: "Email and password required" });
  }

  if (email !== LOGIN_EMAIL || password !== LOGIN_PASSWORD) {
    return res
      .status(401)
      .json({ success: false, error: "Invalid credentials" });
  }

  const sessionId = createSession(email);
  res.cookie("sessionId", sessionId, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 24 * 60 * 60 * 1000,
  });

  res.json({ success: true, message: "Login successful" });
});

// Check authentication
app.get(`${BASE_PATH}/api/auth/check`, (req, res) => {
  const session = validateSession(req);
  res.json({ authenticated: !!session });
});

// Logout
app.post(`${BASE_PATH}/api/logout`, authenticate, (req, res) => {
  const sessionId = req.sessionId;

  // Disconnect WhatsApp
  const client = state.clients.get(sessionId);
  if (client) {
    client.destroy().catch(console.error);
    state.clients.delete(sessionId);
  }

  // Clean up state
  state.sessions.delete(sessionId);
  state.qrCodes.delete(sessionId);
  state.eventListeners.delete(sessionId);

  res.clearCookie("sessionId");
  res.json({ success: true });
});

// Get status
app.get(`${BASE_PATH}/status`, authenticate, (req, res) => {
  const status = getClientStatus(req.sessionId);
  res.json(status);
});

// Get QR code
app.get(`${BASE_PATH}/api/qr`, authenticate, (req, res) => {
  const qr = state.qrCodes.get(req.sessionId);
  const client = state.clients.get(req.sessionId);

  if (client && client.info?.pushname) {
    return res.json({ ready: true });
  }

  if (qr) {
    return res.json({ qr });
  }

  // QR generation in progress
  res.json({ qr: null });
});

// Event stream (SSE)
app.get(`${BASE_PATH}/api/events`, authenticate, (req, res) => {
  const sessionId = req.sessionId;

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");

  if (!state.eventListeners.has(sessionId)) {
    state.eventListeners.set(sessionId, []);
  }

  const listeners = state.eventListeners.get(sessionId);
  listeners.push(res);

  // Send current status
  const status = getClientStatus(sessionId);
  res.write(`data: ${JSON.stringify({ type: "status", data: status })}\n\n`);

  // Keep-alive ping every 30s
  const pingInterval = setInterval(() => {
    if (!res.writableEnded) {
      res.write(": ping\n\n");
    } else {
      clearInterval(pingInterval);
      const idx = listeners.indexOf(res);
      if (idx > -1) listeners.splice(idx, 1);
    }
  }, 30000);

  res.on("close", () => {
    clearInterval(pingInterval);
  });
});

// Disconnect WhatsApp
app.post(`${BASE_PATH}/api/disconnect`, authenticate, async (req, res) => {
  const sessionId = req.sessionId;
  const client = state.clients.get(sessionId);

  try {
    if (client) {
      await client.destroy();
      state.clients.delete(sessionId);
    }

    state.qrCodes.delete(sessionId);
    broadcastToSession(sessionId, { type: "disconnected" });

    res.json({
      success: true,
      message: "WhatsApp disconnected successfully",
    });
  } catch (error) {
    console.error("Disconnect error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to disconnect",
    });
  }
});

// Send message
app.post(`${BASE_PATH}/send-message`, authenticate, async (req, res) => {
  const { phoneNumber, message } = req.body;
  const sessionId = req.sessionId;

  if (!phoneNumber || !message) {
    return res.status(400).json({
      success: false,
      message: "Phone number and message are required",
    });
  }

  const client = state.clients.get(sessionId);

  if (!client || !client.info?.pushname) {
    return res.status(400).json({
      success: false,
      message: "WhatsApp is not connected. Please scan the QR code first.",
    });
  }

  try {
    // Format phone number: remove spaces, dashes, parentheses
    const formattedPhone = phoneNumber
      .replace(/[\s\-\(\)]/g, "")
      .replace(/^\+/, "");

    // Validate phone number format
    if (!/^\d{10,15}$/.test(formattedPhone)) {
      return res.status(400).json({
        success: false,
        message: "Invalid phone number format",
      });
    }

    const chatId = `${formattedPhone}@c.us`;
    await client.sendMessage(chatId, message);

    res.json({
      success: true,
      message: "Message sent successfully",
    });
  } catch (error) {
    console.error("Send message error:", error);
    res.status(500).json({
      success: false,
      message: error.message || "Failed to send message",
    });
  }
});

// Initialize WhatsApp on first request (lazy loading)
app.use(`${BASE_PATH}`, authenticate, async (req, res, next) => {
  const sessionId = req.sessionId;

  try {
    if (!state.clients.has(sessionId)) {
      // Non-blocking initialization
      initializeWhatsAppClient(sessionId).catch((error) => {
        console.error("Client initialization error:", error);
      });
    }
    next();
  } catch (error) {
    console.error("Middleware error:", error);
    next();
  }
});

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// Serve frontend
app.get("/", (req, res) => {
  const indexPath = path.join(__dirname, "public", "index.html");
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(200).json({
      message: "WhatsApp OTP Service",
      status: "running",
      setupUrl: "/otp-service/",
    });
  }
});

app.get("/otp-service/", (req, res) => {
  const indexPath = path.join(__dirname, "public", "index.html");
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).json({
      error: "Frontend not found",
      message: "Please place index.html in the public/ directory",
      setupGuide: "See SETUP.md for instructions",
    });
  }
});

// Serve static files (CSS, JS, images, etc.) - placed after API routes
app.use(express.static("public"));

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: "Not Found",
    path: req.path,
    method: req.method,
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res.status(500).json({
    error: "Internal Server Error",
    message:
      process.env.NODE_ENV === "production"
        ? "An error occurred"
        : err.message,
  });
});

// ==================== SERVER STARTUP ====================

app.listen(PORT, () => {
  console.log(`WhatsApp OTP Service running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
});

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("SIGTERM received, cleaning up...");
  
  state.clients.forEach((client) => {
    client.destroy().catch(console.error);
  });
  
  state.eventListeners.forEach((listeners) => {
    listeners.forEach((res) => res.end());
  });

  process.exit(0);
});