const express = require("express");
const { Client, LocalAuth } = require("whatsapp-web.js");
const qrcode = require("qrcode-terminal");
const fs = require("fs");
const app = express();
const port = 3002;

// Clear the session directory if it has issues
try {
  const sessionDir = "./.wwebjs_auth/session";
  if (fs.existsSync(sessionDir)) {
    console.log("Checking session directory...");
  }
} catch (error) {
  console.error("Error checking session directory:", error);
}

// Determine a usable Chromium/Chrome/Edge executable
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
  ];

  const candidates =
    process.platform === "win32" ? windowsCandidates : linuxCandidates;

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      console.log(`Using detected browser executable: ${candidate}`);
      return candidate;
    }
  }

  console.warn(
    "No browser executable found in default locations; falling back to Puppeteer's bundled Chromium (ensure 'puppeteer' package is installed)."
  );
  return undefined; // Allow puppeteer to use its bundled copy if present
}

const client = new Client({
  authStrategy: new LocalAuth({ clientId: "whatsapp-otp" }),
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

// Create an authenticated flag
let isAuthenticated = false;
let isReady = false;

// Helper function to check if client is truly ready
function isClientReady() {
  try {
    // Check if client is initialized and has info
    if (!isAuthenticated || !isReady) {
      return false;
    }
    
    // Try to access client state safely
    const info = client.info;
    if (!info || !info.wid) {
      return false;
    }
    
    return true;
  } catch (error) {
    return false;
  }
}

// QR code event
client.on("qr", (qr) => {
  console.log("New QR code received, please scan:");
  qrcode.generate(qr, { small: true });
  isAuthenticated = false;
  isReady = false;
});

// Auth failure event
client.on("auth_failure", (msg) => {
  console.error("WhatsApp authentication failed:", msg);
  isAuthenticated = false;
  isReady = false;
});

// Ready event
client.on("ready", () => {
  console.log("WhatsApp Client is ready to send messages!");
  isAuthenticated = true;
  isReady = true;
  
  // Stop the fallback check interval if it's running
  if (readyCheckInterval) {
    clearInterval(readyCheckInterval);
    readyCheckInterval = null;
  }
});

// Disconnected event
client.on("disconnected", (reason) => {
  console.log("WhatsApp was disconnected:", reason);
  isAuthenticated = false;
  isReady = false;
  
  // Stop the fallback check interval
  if (readyCheckInterval) {
    clearInterval(readyCheckInterval);
    readyCheckInterval = null;
  }
  
  // Attempt to reconnect
  setTimeout(() => {
    console.log("Attempting to reconnect...");
    client.initialize().catch((err) => {
      console.error("Failed to reconnect:", err);
    });
  }, 5000);
});

// Loading screen event
client.on("loading_screen", (percent, message) => {
  console.log(`Loading: ${percent}% - ${message}`);
  
  // If loading reaches 100%, try to mark as ready after a short delay
  if (percent === 100) {
    setTimeout(async () => {
      try {
        // Check if client info is available
        if (client.info && client.info.wid) {
          console.log("Loading complete, client appears ready");
          isReady = true;
        }
      } catch (error) {
        console.log("Waiting for ready event...");
      }
    }, 2000); // Wait 2 seconds after 100% to see if ready event fires
  }
});

// Remote session saved event
client.on("remote_session_saved", () => {
  console.log("Remote session saved successfully");
});

// Add a fallback: periodically check if client is ready even without ready event
let readyCheckInterval = null;

// Start checking for readiness after authentication
client.on("authenticated", () => {
  console.log("WhatsApp authentication successful!");
  isAuthenticated = true;
  isReady = false;
  
  // Start periodic check for readiness
  if (readyCheckInterval) {
    clearInterval(readyCheckInterval);
  }
  
  readyCheckInterval = setInterval(() => {
    if (isAuthenticated && !isReady) {
      try {
        if (client.info && client.info.wid) {
          console.log("Client detected as ready (fallback check)");
          isReady = true;
          if (readyCheckInterval) {
            clearInterval(readyCheckInterval);
            readyCheckInterval = null;
          }
        }
      } catch (error) {
        // Client not ready yet, continue checking
      }
    } else if (isReady && readyCheckInterval) {
      // Already ready, stop checking
      clearInterval(readyCheckInterval);
      readyCheckInterval = null;
    }
  }, 3000); // Check every 3 seconds
});

// Utility function to format phone number
function formatPhoneNumber(phoneNumber) {
  // Ensure phone number is formatted correctly
  let formattedNumber = phoneNumber.toString().replace(/[^0-9]/g, "");

  // If number starts with 0, replace with country code 963
  if (formattedNumber.startsWith("0")) {
    formattedNumber = "963" + formattedNumber.slice(1);
  }

  return formattedNumber + "@c.us";
}

// Send OTP function with better error handling
async function sendOTP(phoneNumber, otp) {
  if (!isClientReady()) {
    console.error("Cannot send OTP: WhatsApp client not ready");
    throw new Error("WhatsApp client not ready");
  }

  const chatId = formatPhoneNumber(phoneNumber);
  const message = ` رمز التحقق هو : 
     ${otp}`;

  console.log(`Attempting to send OTP to ${chatId}`);

  try {
    // Wait a bit to ensure client internal state is fully ready
    await new Promise(resolve => setTimeout(resolve, 300));
    
    // Send message - WhatsApp Web will create chat if it doesn't exist
    const response = await client.sendMessage(chatId, message);
    console.log("OTP sent successfully:", response.id._serialized);
    return response;
  } catch (error) {
    console.error("Error sending OTP:", error);
    
    // If error is about undefined sendSeen or internal state, client might not be fully ready
    if (error.message && (error.message.includes("sendSeen") || error.message.includes("Cannot read properties"))) {
      console.error("Client internal state not ready, marking as not ready");
      isReady = false;
      throw new Error("WhatsApp client internal state not ready. Please try again in a few seconds.");
    }
    
    throw error;
  }
}

// Send custom message function
async function sendCustomMessage(phoneNumber, message) {
  if (!isClientReady()) {
    console.error("Cannot send message: WhatsApp client not ready");
    throw new Error("WhatsApp client not ready");
  }

  const chatId = formatPhoneNumber(phoneNumber);

  console.log(`Attempting to send custom message to ${chatId}`);

  try {
    // Wait a bit to ensure client internal state is fully ready
    await new Promise(resolve => setTimeout(resolve, 300));
    
    // Send message - WhatsApp Web will create chat if it doesn't exist
    const response = await client.sendMessage(chatId, message);
    console.log("Custom message sent successfully:", response.id._serialized);
    return response;
  } catch (error) {
    console.error("Error sending custom message:", error);
    
    // If error is about undefined sendSeen or internal state, client might not be fully ready
    if (error.message && (error.message.includes("sendSeen") || error.message.includes("Cannot read properties"))) {
      console.error("Client internal state not ready, marking as not ready");
      isReady = false;
      throw new Error("WhatsApp client internal state not ready. Please try again in a few seconds.");
    }
    
    throw error;
  }
}

// Express setup
app.use(express.json());

// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "ok",
    whatsappAuthenticated: isAuthenticated,
    whatsappReady: isReady,
    clientReady: isClientReady(),
  });
});

// Status endpoint
app.get("/status", (req, res) => {
  res.status(200).json({
    whatsappAuthenticated: isAuthenticated,
    whatsappReady: isReady,
    clientReady: isClientReady(),
    timestamp: new Date().toISOString(),
  });
});

// OTP endpoint with better error handling
app.post("/send-otp", async (req, res) => {
  const { phoneNumber, otp, purpose } = req.body;

  console.log(`Received OTP request for phone: ${phoneNumber}, purpose: ${purpose || 'not specified'}`);

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
    res.status(200).json({
      success: true,
      message: "OTP sent successfully",
      otpSent: true,
    });
  } catch (error) {
    console.error("Failed to send OTP:", error);
    res.status(500).json({
      success: false,
      message: "Failed to send OTP",
      otpSent: false,
    });
  }
});

// New endpoint for sending custom messages
app.post("/send-message", async (req, res) => {
  const { phoneNumber, message } = req.body;

  console.log(`Received custom message request for phone: ${phoneNumber}`);

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
    res.status(200).json({
      success: true,
      message: "Message sent successfully",
      messageSent: true,
    });
  } catch (error) {
    console.error("Failed to send WhatsApp message:", error);
    res.status(500).json({
      success: false,
      message: "Failed to send WhatsApp message",
      messageSent: false,
    });
  }
});

// Start the server first, then initialize WhatsApp client
app.listen(port, "0.0.0.0", () => {
  console.log(`Server is running on http://0.0.0.0:${port}`);

  // Initialize WhatsApp client
  console.log("Starting WhatsApp client...");
  setTimeout(() => {
    client.initialize().catch((err) => {
      console.error("Failed to initialize WhatsApp client:", err);
    });
  }, 2000); // Small delay before initialization
});

// Handle process termination
process.on("SIGINT", async () => {
  console.log("Shutting down...");
  if (client) {
    try {
      await client.destroy();
      console.log("WhatsApp client destroyed");
    } catch (err) {
      console.error("Error destroying WhatsApp client:", err);
    }
  }
  process.exit(0);
});
