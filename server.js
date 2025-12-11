/**
 * server.js
 *
 * Goals:
 * - Preserve existing endpoints + DTOs + flows:
 *   GET  /health
 *   GET  /status
 *   POST /send-otp      { phoneNumber, otp, purpose } -> same response shape
 *   POST /send-message  { phoneNumber, message }      -> same response shape
 * - Deterministic readiness:
 *   - Authenticated + getState() == CONNECTED
 *   - AND WhatsApp Web runtime injected (Store/WWebJS)
 *   - AND warmup completed (presence call succeeds)
 * - Self-healing:
 *   - probe loop monitors state
 *   - watchdog restarts on stuck loading / unstable runtime
 * - Minimize noisy logs (rate-limited)
 */

"use strict";

const express = require("express");
const { Client, LocalAuth } = require("whatsapp-web.js");
const qrcode = require("qrcode-terminal");
const fs = require("fs");

const app = express();
const port = process.env.PORT ? Number(process.env.PORT) : 3002;

app.use(express.json());

/* ------------------------------ Configuration ------------------------------ */

const CLIENT_ID = process.env.WWEBJS_CLIENT_ID || "whatsapp-otp";
const AUTH_DIR = process.env.WWEBJS_AUTH_DIR || "./.wwebjs_auth";

// Probing / recovery
const PROBE_INTERVAL_MS = 3000;
const WATCHDOG_STUCK_MS = 120000; // 2 minutes at >=90% loading without stable ready -> restart
const RESTART_BACKOFF_MS = 5000;

// Warmup / runtime gates
const POST_CONNECTED_GRACE_MS = 2500; // give WA time after CONNECTED
const WARMUP_TIMEOUT_MS = 25000;
const WARMUP_RETRY_MS = 1200;

// Debug logging
const DEBUG = process.env.DEBUG_WWEBJS === "1";

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
  console.log(`[${nowIso()}] Auth directory ensured: ${AUTH_DIR}`);
} catch (error) {
  console.error(`[${nowIso()}] Error ensuring auth dir:`, safeErr(error));
}

/* ------------------------------ WhatsApp Client ---------------------------- */
/**
 * IMPORTANT:
 * - On Linux VPS in Docker, prefer Puppeteer bundled Chromium (do not pass executablePath).
 * - Keep --no-sandbox flags for containers.
 */
const client = new Client({
  authStrategy: new LocalAuth({ clientId: CLIENT_ID, dataPath: AUTH_DIR }),
  puppeteer: {
    headless: true,
    args: [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
      "--disable-accelerated-2d-canvas",
      "--no-first-run",
      "--no-zygote",
      "--disable-gpu",
      "--disable-extensions",
      "--disable-default-apps",
      "--mute-audio",
      "--hide-scrollbars",
    ],
  },
});

/* ---------------------------- Readiness management -------------------------- */

// Public flags (preserve semantics used by your endpoints)
let isAuthenticated = false; // "session/auth succeeded"
let isReady = false;         // "safe to send" (strict gated)

// Internal diagnostics/state
let lastKnownState = null;
let lastStateAt = null;

let loadingSince = null;
let lastLoadingPercent = null;

let probeTimer = null;
let initializing = false;
let restarting = false;

// Warmup state
let connectedSince = null;
let warmupDone = false;
let warmupInFlight = null;

function resetWarmup(reason) {
  warmupDone = false;
  warmupInFlight = null;
  connectedSince = null;
  if (DEBUG) console.log(`[${nowIso()}] [warmup] reset (${reason})`);
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

function stateIndicatesConnected(state) {
  return state === "CONNECTED";
}

/**
 * Wait until WhatsApp Web runtime objects are present inside the page.
 * This directly addresses the "sendSeen undefined" class of failures,
 * which happens when Store is not injected/ready yet.
 */
async function waitForWWebRuntime(timeoutMs = 20000) {
  const page = client?.pupPage;
  if (!page || typeof page.waitForFunction !== "function") {
    // Best-effort: older/changed internals
    return true;
  }

  try {
    await page.waitForFunction(
      () => {
        // whatsapp-web.js injects helpers; Store is key for message pipeline.
        return !!(window.Store && window.WWebJS);
      },
      { timeout: timeoutMs }
    );
    return true;
  } catch (e) {
    if (DEBUG) console.error(`[${nowIso()}] [warmup] waitForWWebRuntime timeout:`, safeErr(e));
    return false;
  }
}

async function warmupWhatsAppRuntime() {
  if (warmupDone) return true;
  if (!isAuthenticated) return false;
  if (warmupInFlight) return warmupInFlight;

  warmupInFlight = (async () => {
    // Wait a bit after CONNECTED
    if (connectedSince) {
      const elapsed = Date.now() - connectedSince;
      if (elapsed < POST_CONNECTED_GRACE_MS) {
        await sleep(POST_CONNECTED_GRACE_MS - elapsed);
      }
    }

    const runtimeOk = await waitForWWebRuntime(20000);
    if (!runtimeOk) return false;

    const deadline = Date.now() + WARMUP_TIMEOUT_MS;
    while (Date.now() < deadline) {
      try {
        // Presence call is a cheap way to confirm Store pipeline is usable.
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

  if (connected && !connectedSince) connectedSince = Date.now();

  // Warmup must succeed to declare send-ready
  let warmOk = false;
  if (connected) {
    warmOk = await warmupWhatsAppRuntime();
  } else {
    warmOk = false;
    warmupDone = false;
  }

  const readyNow = Boolean(connected && warmOk);

  if (readyNow && !isReady) {
    console.log(`[${nowIso()}] Client is fully send-ready (CONNECTED + warmed).`);
  }
  if (!readyNow && isReady) {
    console.log(
      `[${nowIso()}] Client is no longer send-ready (state=${state}, warmupDone=${warmupDone}).`
    );
  }

  isReady = readyNow;
  return { state, connected, warmOk, readyNow };
}

function startProbeLoop() {
  if (probeTimer) clearInterval(probeTimer);

  probeTimer = setInterval(async () => {
    if (!isAuthenticated) return;

    const { state, readyNow } = await recomputeReadiness();

    if (DEBUG) {
      logEvery(
        "probe.state",
        5000,
        `[${nowIso()}] [probe] state=${state} ready=${readyNow} warmupDone=${warmupDone} loading=${lastLoadingPercent ?? "-"}%`
      );
    }

    // Watchdog: stuck at high loading without stable ready
    if (!readyNow && loadingSince && Date.now() - loadingSince > WATCHDOG_STUCK_MS) {
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

  await sleep(RESTART_BACKOFF_MS);

  loadingSince = null;
  lastLoadingPercent = null;

  restarting = false;
  await initializeClientOnce();
}

/* --------------------------------- Events --------------------------------- */

client.on("qr", (qr) => {
  console.log(`[${nowIso()}] New QR code received, please scan:`);
  qrcode.generate(qr, { small: true });

  isAuthenticated = false;
  isReady = false;

  loadingSince = null;
  lastLoadingPercent = null;
  resetWarmup("qr");
});

client.on("authenticated", () => {
  console.log(`[${nowIso()}] WhatsApp authentication successful!`);
  isAuthenticated = true;
  isReady = false;

  resetWarmup("authenticated");
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
  // Helpful signal, but not trusted alone
  console.log(`[${nowIso()}] WhatsApp 'ready' event fired.`);
  await recomputeReadiness();
});

client.on("disconnected", async (reason) => {
  console.log(`[${nowIso()}] WhatsApp was disconnected:`, reason);

  isAuthenticated = false;
  isReady = false;

  resetWarmup("disconnected");
  stopProbeLoop();

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

function isInternalRaceError(error) {
  const msg = error?.message || "";
  // The known failure signature you are seeing
  return msg.includes("sendSeen") || msg.includes("Cannot read properties of undefined");
}

async function ensureWarmBeforeSend() {
  // Recompute readiness on-demand
  const { readyNow } = await recomputeReadiness();
  if (!readyNow) {
    throw new Error("WhatsApp client not ready");
  }
}

async function sendWithOneRetry(sendFn) {
  try {
    return await sendFn();
  } catch (error) {
    if (!isInternalRaceError(error)) throw error;

    console.error(`[${nowIso()}] Internal state race detected; resetting warmup and retrying once.`);
    resetWarmup("sendMessage-race");
    isReady = false;

    // Give the runtime a moment to settle, then warm again
    await sleep(1500);

    try {
      await ensureWarmBeforeSend();
    } catch (_) {
      // If we cannot become warm quickly, prefer restart rather than repeated failures
      await restartClient("send-race warmup failed");
      await ensureWarmBeforeSend();
    }

    // Retry once
    return await sendFn();
  }
}

async function sendOTP(phoneNumber, otp) {
  if (!isClientReady()) {
    console.error(`[${nowIso()}] Cannot send OTP: WhatsApp client not ready`);
    throw new Error("WhatsApp client not ready");
  }

  const chatId = formatPhoneNumber(phoneNumber);
  const message = ` رمز التحقق هو : 
     ${otp}`;

  console.log(`[${nowIso()}] Attempting to send OTP to ${chatId}`);

  return await sendWithOneRetry(async () => {
    // small jitter
    await sleep(250);
    const response = await client.sendMessage(chatId, message);
    console.log(`[${nowIso()}] OTP sent successfully:`, response?.id?._serialized || "ok");
    return response;
  });
}

async function sendCustomMessage(phoneNumber, message) {
  if (!isClientReady()) {
    console.error(`[${nowIso()}] Cannot send message: WhatsApp client not ready`);
    throw new Error("WhatsApp client not ready");
  }

  const chatId = formatPhoneNumber(phoneNumber);
  console.log(`[${nowIso()}] Attempting to send custom message to ${chatId}`);

  return await sendWithOneRetry(async () => {
    await sleep(250);
    const response = await client.sendMessage(chatId, message);
    console.log(`[${nowIso()}] Custom message sent successfully:`, response?.id?._serialized || "ok");
    return response;
  });
}

/* -------------------------------- Endpoints -------------------------------- */

// Health check endpoint (preserve keys)
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "ok",
    whatsappAuthenticated: isAuthenticated,
    whatsappReady: isReady,
    clientReady: isClientReady(),
  });
});

// Status endpoint (preserve keys + timestamp)
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
  setTimeout(() => {
    initializeClientOnce();
  }, 1500);
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
