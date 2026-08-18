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

/**
 * --------------------------------------------------------------------------
 * Express middleware
 * --------------------------------------------------------------------------
 */

app.use(
  cors({
    origin: FRONTEND_URL,
    methods: ["GET", "POST"],
    credentials: true,
  })
);

app.use(express.json());

/**
 * --------------------------------------------------------------------------
 * Socket.io
 * --------------------------------------------------------------------------
 */

const io = new Server(httpServer, {
  cors: {
    origin: FRONTEND_URL,
    methods: ["GET", "POST"],
    credentials: true,
  },
});

app.set("io", io);

/**
 * --------------------------------------------------------------------------
 * Health endpoint
 * --------------------------------------------------------------------------
 */

app.get("/api/health", (req, res) => {
  res.status(200).json({
    success: true,
    message: "Zero-Trust Threat Detection backend is running.",
  });
});

/**
 * --------------------------------------------------------------------------
 * Alert routes
 * --------------------------------------------------------------------------
 *
 * GET  /api/alerts
 * POST /api/alerts
 */

app.use("/api/alerts", alertRoutes);

/**
 * --------------------------------------------------------------------------
 * Socket connections
 * --------------------------------------------------------------------------
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
 * --------------------------------------------------------------------------
 * Error handler
 * --------------------------------------------------------------------------
 */

app.use((error, req, res, next) => {
  console.error("Unhandled server error:", error);

  res.status(500).json({
    success: false,
    message: "Internal server error.",
  });
});

/**
 * --------------------------------------------------------------------------
 * Start server
 * --------------------------------------------------------------------------
 */

const startServer = () => {
  httpServer.listen(PORT, () => {
    console.log("");
    console.log("==============================================");
    console.log(" Zero-Trust Threat Detection Backend");
    console.log("==============================================");
    console.log(`Server:  http://localhost:${PORT}`);
    console.log(`Health:  http://localhost:${PORT}/api/health`);
    console.log(`Alerts:  http://localhost:${PORT}/api/alerts`);
    console.log("MongoDB: DISABLED");
    console.log("==============================================");
    console.log("");
  });
};

startServer();