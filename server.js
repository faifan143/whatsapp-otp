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

// WhatsApp client setup
const client = new Client({
  authStrategy: new LocalAuth({ clientId: "whatsapp-otp" }),
  puppeteer: {
    headless: true,
    executablePath:
      process.env.PUPPETEER_EXECUTABLE_PATH || "/usr/bin/chromium",
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

// QR code event
client.on("qr", (qr) => {
  console.log("New QR code received, please scan:");
  qrcode.generate(qr, { small: true });
});

// Authentication event
client.on("authenticated", () => {
  console.log("WhatsApp authentication successful!");
  isAuthenticated = true;
});

// Auth failure event
client.on("auth_failure", (msg) => {
  console.error("WhatsApp authentication failed:", msg);
  isAuthenticated = false;
});

// Ready event
client.on("ready", () => {
  console.log("WhatsApp Client is ready to send messages!");
  isAuthenticated = true;
});

// Disconnected event
client.on("disconnected", (reason) => {
  console.log("WhatsApp was disconnected:", reason);
  isAuthenticated = false;
  // Attempt to reconnect
  setTimeout(() => {
    console.log("Attempting to reconnect...");
    client.initialize();
  }, 5000);
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
function sendOTP(phoneNumber, otp) {
  if (!isAuthenticated) {
    console.error("Cannot send OTP: WhatsApp client not authenticated");
    return Promise.reject(new Error("WhatsApp client not authenticated"));
  }

  const chatId = formatPhoneNumber(phoneNumber);
  const message = ` رمز التحقق هو : 
     ${otp}`;

  console.log(`Attempting to send OTP to ${chatId}`);

  return client
    .sendMessage(chatId, message)
    .then((response) => {
      console.log("OTP sent successfully:", response.id._serialized);
      return response;
    })
    .catch((error) => {
      console.error("Error sending OTP:", error);
      throw error;
    });
}

// Send custom message function
function sendCustomMessage(phoneNumber, message) {
  if (!isAuthenticated) {
    console.error("Cannot send message: WhatsApp client not authenticated");
    return Promise.reject(new Error("WhatsApp client not authenticated"));
  }

  const chatId = formatPhoneNumber(phoneNumber);

  console.log(`Attempting to send custom message to ${chatId}`);

  return client
    .sendMessage(chatId, message)
    .then((response) => {
      console.log("Custom message sent successfully:", response.id._serialized);
      return response;
    })
    .catch((error) => {
      console.error("Error sending custom message:", error);
      throw error;
    });
}

// Express setup
app.use(express.json());

// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "ok",
    whatsappAuthenticated: isAuthenticated,
  });
});

// Status endpoint
app.get("/status", (req, res) => {
  res.status(200).json({
    whatsappAuthenticated: isAuthenticated,
    timestamp: new Date().toISOString(),
  });
});

// OTP endpoint with better error handling
app.post("/send-otp", async (req, res) => {
  const { phoneNumber, otp } = req.body;

  console.log(`Received OTP request for phone: ${phoneNumber}`);

  if (!phoneNumber || !otp) {
    return res.status(400).json({
      success: false,
      error: "Phone number and OTP are required",
    });
  }

  if (!isAuthenticated) {
    return res.status(503).json({
      success: false,
      error: "WhatsApp service not ready. Please wait for authentication.",
    });
  }

  try {
    await sendOTP(phoneNumber, otp);
    res.status(200).json({
      success: true,
      message: "OTP sent successfully",
    });
  } catch (error) {
    console.error("Failed to send OTP:", error);
    res.status(500).json({
      success: false,
      error: "Failed to send OTP",
      details: error.message,
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
      error: "Phone number and message are required",
    });
  }

  if (!isAuthenticated) {
    return res.status(503).json({
      success: false,
      error: "WhatsApp service not ready. Please wait for authentication.",
    });
  }

  try {
    await sendCustomMessage(phoneNumber, message);
    res.status(200).json({
      success: true,
      message: "Custom message sent successfully",
    });
  } catch (error) {
    console.error("Failed to send custom message:", error);
    res.status(500).json({
      success: false,
      error: "Failed to send custom message",
      details: error.message,
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
