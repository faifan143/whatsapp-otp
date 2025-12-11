/**
 * server.js
 *
 * Goals:
 * - Preserve existing endpoints + DTOs + flows:
 *   GET  /health
 *   GET  /status
 *   POST /send-otp      { phoneNumber, otp, purpose } -> same response shape
 *   POST /send-message  { phoneNumber, message }      -> same response shape
 * - Make readiness deterministic (state-driven), observable, and self-healing.
 * - Avoid silent failures; add bounded logging.
 * - Add watchdog for "stuck at 99%" and recovery (restart client).
 * - VPS/headless-safe: prevent first-send race ("sendSeen undefined") via warmup + send queue.
 */

const express = require("express");
const { Client, LocalAuth } = require("whatsapp-web.js");
const qrcode = require("qrcode-terminal");
const fs = require("fs");

const app = express();
const port = 3002;

app.use(express.json());

/* ------------------------------ Configuration ------------------------------ */

const CLIENT_ID = "whatsapp-otp";

// Watchdog / probe tuning
const PROBE_INTERVAL_MS = 3000;
const WATCHDOG_STUCK_MS = 120000; // 2 minutes at >=90% loading without CONNECTED -> restart
const RESTART_BACKOFF_MS = 5000;

// Warmup (VPS/headless)
const WARMUP_TIMEOUT_MS = 15000;   // time budget to warm WhatsApp runtime
const WARMUP_RETRY_MS = 500;       // retry delay for warmup attempts
const POST_CONNECTED_GRACE_MS = 1500; // extra grace after CONNECTED before warmup (reduces flakiness)

// When true, we log additional details (still rate-limited)
const DEBUG = process.env.DEBUG_WWEBJS === "1";

// If you use Docker, prefer mounting this directory on the host (you already do)
const AUTH_DIR = "./.wwebjs_auth";

/* ------------------------------ Small utilities ---------------------------- */

function nowIso() {
  return new Date().toISOString();
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function safeErr(err) {
  return {
    name: err?.name,
    message: err?.message,
    stackTop: (err?.stack || "").split("\n").slice(0, 3).join("\n"),
  };
}

// Rate-limited logger
let _lastLogAt = new Map();
function logEvery(key, ms, ...args) {
  const t = Date.now();
  const last = _lastLogAt.get(key) || 0;
  if (t - last >= ms) {
    _lastLogAt.set(key, t);
    console.log(...args);
  }
}

/* ----------------------- Session dir sanity check -------------------------- */

try {
  if (!fs.existsSync(AUTH_DIR)) fs.mkdirSync(AUTH_DIR, { recursive: true });
  // Do not wipe automatically in prod; it can force QR re-scan.
  console.log(`[${nowIso()}] Auth directory ensured: ${AUTH_DIR}`);
} catch (error) {
  console.error(`[${nowIso()}] Error ensuring auth dir:`, safeErr(error));
}

/* -------------------- Chromium/Chrome executable resolver ------------------ */

function resolveExecutablePath() {
  if (process.env.PUPPETEER_EXECUTABLE_PATH) {
    return process.env.PUPPETEER_EXECUTABLE_PATH;
  }

  const windowsCandidates = [
    "C:\\\\Program Files\\\\Google\\\\Chrome\\\\Application\\\\chrome.exe",
    "C:\\\\Program Files (x86)\\\\Google\\\\Chrome\\\\Application\\\\chrome.exe",
    "C:\\\\Program Files\\\\Microsoft\\\\Edge\\\\Application\\\\msedge.exe",
    "C:\\\\Program Files (x86)\\\\Microsoft\\\\Edge\\\\Application\\\\msedge.exe",
  ];

  const linuxCandidates = [
    "/usr/bin/chromium-browser",
    "/usr/bin/chromium",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/snap/bin/chromium",
  ];

  const candidates = process.platform === "win32" ? windowsCandidates : linuxCandidates;

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      console.log(`[${nowIso()}] Using detected browser executable: ${candidate}`);
      return candidate;
    }
  }

  console.warn(
    `[${nowIso()}] No browser executable found in defaults; Puppeteer will use its own Chromium if available.`
  );
  return undefined;
}

/* ------------------------------ WhatsApp Client ---------------------------- */

const client = new Client({
  authStrategy: new LocalAuth({ clientId: CLIENT_ID }),
  puppeteer: {
    headless: true,
    executablePath: resolveExecutablePath(),
    args: [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
      "--disable-accelerated-2d-canvas",
      "--no-first-run",
      "--no-zygote",
      "--disable-gpu",
      "--disable-extensions",
      "--disable-component-extensions-with-background-pages",
      "--disable-default-apps",
      "--mute-audio",
      "--hide-scrollbars",
    ],
  },
});

/* ---------------------------- Readiness management -------------------------- */

// Public flags (preserve semantics used by your endpoints)
let isAuthenticated = false; // "session/auth succeeded"
let isReady = false;         // "safe to send"

// Internal diagnostics / state
let lastKnownState = null;   // from client.getState()
let lastStateAt = null;

let loadingSince = null;
let lastLoadingPercent = null;

let probeTimer = null;

let initializing = false;
let restarting = false;

// VPS/headless: prevent "CONNECTED but internal runtime not hydrated yet"
let warmupDone = false;
let warmupInFlight = null;
let connectedSince = null;

// In-process send queue to avoid concurrent first-send races
let sendLock = Promise.resolve();
function withSendLock(fn) {
  sendLock = sendLock.then(fn, fn);
  return sendLock;
}

function resetWarmup(reason) {
  if (DEBUG) console.log(`[${nowIso()}] [warmup] reset (${reason})`);
  warmupDone = false;
  warmupInFlight = null;
  connectedSince = null;
}

async function getClientStateSafe() {
  try {
    const state = await client.getState();
    lastKnownState = state;
    lastStateAt = Date.now();
    return state;
  } catch (e) {
    if (DEBUG) logEvery("getState.err", 5000, `[${nowIso()}] [probe] getState() threw:`, safeErr(e));
    return null;
  }
}

// Strict state definition of connected
function stateIndicatesConnected(state) {
  return state === "CONNECTED";
}

/**
 * Warm-up gate (VPS/headless safe):
 * WhatsApp Web may report CONNECTED before internal modules are fully ready.
 * We "touch" the runtime via presence calls and wait a short grace period.
 * This avoids the common first-send failure: sendSeen undefined.
 */
async function warmupWhatsAppRuntime() {
  if (warmupDone) return true;
  if (!isAuthenticated) return false;

  if (warmupInFlight) return warmupInFlight;

  warmupInFlight = (async () => {
    // Give WhatsApp Web a small grace period after CONNECTED
    if (connectedSince) {
      const elapsed = Date.now() - connectedSince;
      if (elapsed < POST_CONNECTED_GRACE_MS) {
        await sleep(POST_CONNECTED_GRACE_MS - elapsed);
      }
    }

    const deadline = Date.now() + WARMUP_TIMEOUT_MS;

    while (Date.now() < deadline) {
      try {
        // This touches the internal runtime; in the failure window it often throws.
        await client.sendPresenceAvailable();
        warmupDone = true;
        if (DEBUG) console.log(`[${nowIso()}] [warmup] runtime warmed successfully`);
        return true;
      } catch (e) {
        if (DEBUG) logEvery("warmup.err", 2000, `[${nowIso()}] [warmup] not ready yet:`, safeErr(e));
        await sleep(WARMUP_RETRY_MS);
      }
    }

    return false;
  })();

  const ok = await warmupInFlight;
  warmupInFlight = null;
  return ok;
}

async function recomputeReadiness() {
  const state = await getClientStateSafe();
  const connected = isAuthenticated && stateIndicatesConnected(state);

  if (connected && !connectedSince) {
    connectedSince = Date.now();
  }
  if (!connected) {
    // if we drop from connected, warmup is no longer valid
    resetWarmup("state-not-connected");
  }

  let readyNow = false;
  if (connected) {
    // Only become "ready" after warmup completes
    readyNow = await warmupWhatsAppRuntime();
  }

  if (readyNow && !isReady) {
    console.log(`[${nowIso()}] Client is fully send-ready (CONNECTED + warmed).`);
  }
  if (!readyNow && isReady) {
    console.log(`[${nowIso()}] Client is no longer send-ready (state=${state}).`);
  }

  isReady = readyNow;
  return { state, readyNow };
}

function startProbeLoop() {
  if (probeTimer) clearInterval(probeTimer);

  probeTimer = setInterval(async () => {
    if (!isAuthenticated) return;

    // 1) Recompute readiness based on getState() + warmup
    const { state, readyNow } = await recomputeReadiness();

    if (DEBUG) {
      logEvery(
        "probe.state",
        5000,
        `[${nowIso()}] [probe] state=${state} ready=${readyNow} warmupDone=${warmupDone} loading=${lastLoadingPercent ?? "-"}%`
      );
    }

    // 2) Watchdog: if we are stuck at high loading for too long without CONNECTED, restart
    if (!stateIndicatesConnected(state) && loadingSince && Date.now() - loadingSince > WATCHDOG_STUCK_MS) {
      const pct = lastLoadingPercent ?? "unknown";
      await restartClient(`loading stuck at ${pct}% for >${WATCHDOG_STUCK_MS / 1000}s`);
      loadingSince = null;
      lastLoadingPercent = null;
    }
  }, PROBE_INTERVAL_MS);
}

function stopProbeLoop() {
  if (probeTimer) clearInterval(probeTimer);
  probeTimer = null;
}

async function initializeClientOnce() {
  if (initializing) return;
  initializing = true;
  try {
    console.log(`[${nowIso()}] Starting WhatsApp client...`);
    await client.initialize();
  } catch (e) {
    console.error(`[${nowIso()}] Failed to initialize WhatsApp client:`, safeErr(e));
  } finally {
    initializing = false;
  }
}

async function restartClient(reason) {
  if (restarting) return;
  restarting = true;

  console.log(`[${nowIso()}] [recovery] Restarting WhatsApp client. Reason: ${reason}`);

  // Force flags down immediately
  isReady = false;
  resetWarmup("restart");

  try {
    stopProbeLoop();
  } catch (_) {}

  try {
    await client.destroy();
  } catch (e) {
    console.error(`[${nowIso()}] [recovery] destroy() error:`, safeErr(e));
  }

  // Small backoff to avoid tight crash loops
  await sleep(RESTART_BACKOFF_MS);

  // Reset load tracking
  loadingSince = null;
  lastLoadingPercent = null;

  // Re-init
  restarting = false;
  await initializeClientOnce();
}

/* --------------------------------- Events --------------------------------- */

client.on("qr", (qr) => {
  console.log(`[${nowIso()}] New QR code received, please scan:`);
  qrcode.generate(qr, { small: true });

  isAuthenticated = false;
  isReady = false;

  resetWarmup("qr");

  // Reset diagnostics
  loadingSince = null;
  lastLoadingPercent = null;
});

client.on("authenticated", () => {
  console.log(`[${nowIso()}] WhatsApp authentication successful!`);
  isAuthenticated = true;
  isReady = false;

  resetWarmup("authenticated");

  // Start probing readiness continuously (do not rely on "ready" event)
  startProbeLoop();
});

client.on("auth_failure", (msg) => {
  console.error(`[${nowIso()}] WhatsApp authentication failed:`, msg);
  isAuthenticated = false;
  isReady = false;
  resetWarmup("auth_failure");
  stopProbeLoop();
});

client.on("ready", async () => {
  // Keep this as a helpful signal, but do not trust it alone.
  console.log(`[${nowIso()}] WhatsApp 'ready' event fired.`);
  // Recompute using getState() + warmup to confirm send-readiness
  await recomputeReadiness();
});

client.on("disconnected", async (reason) => {
  console.log(`[${nowIso()}] WhatsApp was disconnected:`, reason);

  isAuthenticated = false;
  isReady = false;

  resetWarmup("disconnected");

  stopProbeLoop();

  // Attempt recovery (single path)
  await restartClient(`disconnected: ${reason}`);
});

client.on("loading_screen", (percent, message) => {
  console.log(`[${nowIso()}] Loading: ${percent}% - ${message}`);

  if (percent >= 90) {
    if (!loadingSince) loadingSince = Date.now();
    lastLoadingPercent = percent;
  } else {
    loadingSince = null;
    lastLoadingPercent = null;
  }
});

client.on("remote_session_saved", () => {
  console.log(`[${nowIso()}] Remote session saved successfully`);
});

/* ------------------------------ Formatting helpers ------------------------- */

function formatPhoneNumber(phoneNumber) {
  let formattedNumber = phoneNumber.toString().replace(/[^0-9]/g, "");

  // If number starts with 0, replace with country code 963
  if (formattedNumber.startsWith("0")) {
    formattedNumber = "963" + formattedNumber.slice(1);
  }

  return formattedNumber + "@c.us";
}

/* ------------------------------- Send functions ---------------------------- */

function isClientReady() {
  return isAuthenticated && isReady;
}

function isInternalRaceError(err) {
  const msg = err?.message || "";
  return msg.includes("sendSeen") || msg.includes("Cannot read properties");
}

async function ensureWarmBeforeSend() {
  // Guard in case a request hits right at the moment CONNECTED flips.
  if (!warmupDone) {
    const ok = await warmupWhatsAppRuntime();
    if (!ok) {
      throw new Error("WhatsApp client internal state not ready. Please try again in a few seconds.");
    }
  }
}

async function sendOTP(phoneNumber, otp) {
  return withSendLock(async () => {
    if (!isClientReady()) {
      console.error(`[${nowIso()}] Cannot send OTP: WhatsApp client not ready`);
      throw new Error("WhatsApp client not ready");
    }

    await ensureWarmBeforeSend();

    const chatId = formatPhoneNumber(phoneNumber);
    const message = ` رمز التحقق هو : 
     ${otp}`;

    console.log(`[${nowIso()}] Attempting to send OTP to ${chatId}`);

    try {
      // Small jitter to reduce race conditions immediately after warmup
      await sleep(300);

      const response = await client.sendMessage(chatId, message);
      console.log(`[${nowIso()}] OTP sent successfully:`, response?.id?._serialized || "ok");
      return response;
    } catch (error) {
      console.error(`[${nowIso()}] Error sending OTP:`, safeErr(error));

      if (isInternalRaceError(error)) {
        console.error(`[${nowIso()}] Internal state race detected; resetting warmup and retry gate.`);
        // Do not auto-resend here (avoid duplicates). Force re-warmup then caller retries.
        isReady = false;
        resetWarmup("sendOTP-race");
        throw new Error("WhatsApp client internal state not ready. Please try again in a few seconds.");
      }

      throw error;
    }
  });
}

async function sendCustomMessage(phoneNumber, message) {
  return withSendLock(async () => {
    if (!isClientReady()) {
      console.error(`[${nowIso()}] Cannot send message: WhatsApp client not ready`);
      throw new Error("WhatsApp client not ready");
    }

    await ensureWarmBeforeSend();

    const chatId = formatPhoneNumber(phoneNumber);
    console.log(`[${nowIso()}] Attempting to send custom message to ${chatId}`);

    try {
      await sleep(300);

      const response = await client.sendMessage(chatId, message);
      console.log(`[${nowIso()}] Custom message sent successfully:`, response?.id?._serialized || "ok");
      return response;
    } catch (error) {
      console.error(`[${nowIso()}] Error sending custom message:`, safeErr(error));

      if (isInternalRaceError(error)) {
        console.error(`[${nowIso()}] Internal state race detected; resetting warmup and retry gate.`);
        isReady = false;
        resetWarmup("sendMessage-race");
        throw new Error("WhatsApp client internal state not ready. Please try again in a few seconds.");
      }

      throw error;
    }
  });
}

/* -------------------------------- Endpoints -------------------------------- */

// Health check endpoint (preserve keys; add optional diagnostics)
app.get("/health", async (req, res) => {
  res.status(200).json({
    status: "ok",
    whatsappAuthenticated: isAuthenticated,
    whatsappReady: isReady,
    clientReady: isClientReady(),
  });
});

// Status endpoint (preserve keys; include timestamp)
app.get("/status", (req, res) => {
  res.status(200).json({
    whatsappAuthenticated: isAuthenticated,
    whatsappReady: isReady,
    clientReady: isClientReady(),
    timestamp: new Date().toISOString(),
  });
});

// OTP endpoint (preserve DTO + flow + response schema)
app.post("/send-otp", async (req, res) => {
  const { phoneNumber, otp, purpose } = req.body;

  console.log(
    `[${nowIso()}] Received OTP request for phone: ${phoneNumber}, purpose: ${purpose || "not specified"}`
  );

  if (!phoneNumber || !otp) {
    return res.status(400).json({
      success: false,
      message: "Phone number and OTP are required",
      otpSent: false,
    });
  }

  if (!isClientReady()) {
    return res.status(503).json({
      success: false,
      message: "WhatsApp service not ready. Please wait for authentication.",
      otpSent: false,
    });
  }

  try {
    await sendOTP(phoneNumber, otp);
    return res.status(200).json({
      success: true,
      message: "OTP sent successfully",
      otpSent: true,
    });
  } catch (error) {
    console.error(`[${nowIso()}] Failed to send OTP:`, safeErr(error));
    return res.status(500).json({
      success: false,
      message: "Failed to send OTP",
      otpSent: false,
    });
  }
});

// Custom message endpoint (preserve DTO + flow + response schema)
app.post("/send-message", async (req, res) => {
  const { phoneNumber, message } = req.body;

  console.log(`[${nowIso()}] Received custom message request for phone: ${phoneNumber}`);

  if (!phoneNumber || !message) {
    return res.status(400).json({
      success: false,
      message: "Phone number and message are required",
      messageSent: false,
    });
  }

  if (!isClientReady()) {
    return res.status(503).json({
      success: false,
      message: "WhatsApp service not ready. Please wait for authentication.",
      messageSent: false,
    });
  }

  try {
    await sendCustomMessage(phoneNumber, message);
    return res.status(200).json({
      success: true,
      message: "Message sent successfully",
      messageSent: true,
    });
  } catch (error) {
    console.error(`[${nowIso()}] Failed to send WhatsApp message:`, safeErr(error));
    return res.status(500).json({
      success: false,
      message: "Failed to send WhatsApp message",
      messageSent: false,
    });
  }
});

/* ------------------------------- Startup / Shutdown ------------------------- */

app.listen(port, "0.0.0.0", () => {
  console.log(`[${nowIso()}] Server is running on http://0.0.0.0:${port}`);
  // Delay init slightly to ensure logs/IO are ready
  setTimeout(() => {
    initializeClientOnce();
  }, 2000);
});

process.on("SIGINT", async () => {
  console.log(`[${nowIso()}] Shutting down...`);
  stopProbeLoop();
  try {
    await client.destroy();
    console.log(`[${nowIso()}] WhatsApp client destroyed`);
  } catch (err) {
    console.error(`[${nowIso()}] Error destroying WhatsApp client:`, safeErr(err));
  }
  process.exit(0);
});
