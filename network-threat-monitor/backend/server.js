require("dotenv").config();

const express = require("express");
const http = require("http");
const cors = require("cors");
const { Server } = require("socket.io");

const alertRoutes = require("./routes/alert.routes");

const app = express();
const httpServer = http.createServer(app);

const PORT = Number(process.env.PORT) || 5000;

const FRONTEND_URL =
  process.env.FRONTEND_URL || "http://localhost:5173";

console.log("Frontend origin:", FRONTEND_URL);

/**
 * CORS
 */
app.use(
  cors({
    origin: true,
    methods: ["GET", "POST", "OPTIONS"],
  })
);

/**
 * JSON body parser
 */
app.use(express.json());

/**
 * Socket.io
 */
const io = new Server(httpServer, {
  cors: {
    origin: FRONTEND_URL,
    methods: ["GET", "POST"],
    credentials: false,
  },
});

app.set("io", io);

/**
 * Root
 */
app.get("/", (req, res) => {
  res.status(200).json({
    success: true,
    message: "Zero-Trust Threat Detection Backend is running.",
  });
});

/**
 * Health
 */
app.get("/api/health", (req, res) => {
  res.status(200).json({
    success: true,
    message: "Zero-Trust Threat Detection backend is running.",
  });
});

/**
 * Alerts
 */
app.use("/api/alerts", alertRoutes);

/**
 * Socket connections
 */
io.on("connection", (socket) => {
  console.log(`Socket client connected: ${socket.id}`);

  socket.on("disconnect", (reason) => {
    console.log(
      `Socket client disconnected: ${socket.id} (${reason})`
    );
  });
});

/**
 * Error handler
 */
app.use((error, req, res, next) => {
  console.error("Unhandled server error:", error);

  res.status(500).json({
    success: false,
    message: "Internal server error.",
  });
});

/**
 * Start server
 */
httpServer.listen(PORT, () => {
  console.log("");
  console.log("==============================================");
  console.log(" Zero-Trust Threat Detection Backend");
  console.log("==============================================");
  console.log(`Server:   http://127.0.0.1:${PORT}`);
  console.log(`Health:   http://127.0.0.1:${PORT}/api/health`);
  console.log(`Alerts:   http://127.0.0.1:${PORT}/api/alerts`);
  console.log(`Frontend: ${FRONTEND_URL}`);
  console.log("==============================================");
  console.log("");
});