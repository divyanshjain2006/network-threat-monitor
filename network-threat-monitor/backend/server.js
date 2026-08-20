require("dotenv").config();

const express = require("express");
const http = require("http");
const cors = require("cors");
const { Server } = require("socket.io");

const alertRoutes = require("./routes/alert.routes");
const telemetryRoutes = require("./routes/telemetry.routes");
const incidentRoutes = require("./routes/incident.routes");
const responseRoutes = require("./routes/response.routes");
const simulatorRoutes = require("./routes/simulator.routes");

const app = express();
const httpServer = http.createServer(app);

const PORT = Number(process.env.PORT) || 5000;

/**
 * --------------------------------------------------------------------------
 * CORS
 * --------------------------------------------------------------------------
 */

const corsOptions = {
  origin: true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type"],
  credentials: false,
};

app.use(cors(corsOptions));

/**
 * --------------------------------------------------------------------------
 * JSON BODY PARSER
 * --------------------------------------------------------------------------
 *
 * This MUST come before API route registration.
 */
app.use(express.json());



/**
 * --------------------------------------------------------------------------
 * Socket.io
 * --------------------------------------------------------------------------
 */

const io = new Server(httpServer, {
  cors: corsOptions,
});

app.set("io", io);

/**
 * --------------------------------------------------------------------------
 * Root
 * --------------------------------------------------------------------------
 */

app.get("/", (req, res) => {
  res.status(200).json({
    success: true,
    message:
      "Zero-Trust Threat Detection Backend is running.",
  });
});

/**
 * --------------------------------------------------------------------------
 * Health
 * --------------------------------------------------------------------------
 */

app.get("/api/health", (req, res) => {
  res.status(200).json({
    success: true,
    message:
      "Zero-Trust Threat Detection backend is running.",
    timestamp: new Date().toISOString(),
  });
});

/**
 * --------------------------------------------------------------------------
 * API ROUTES
 * --------------------------------------------------------------------------
 */

app.use(
  "/api/alerts",
  alertRoutes
);

app.use(
  "/api/telemetry",
  telemetryRoutes
);

app.use(
  "/api/incidents",
  incidentRoutes
);

app.use(
  "/api/responses",
  responseRoutes
);

app.use(
  "/api/simulator",
  simulatorRoutes
);

/**
 * --------------------------------------------------------------------------
 * Socket connections
 * --------------------------------------------------------------------------
 */

io.on("connection", (socket) => {
  console.log(
    `Socket client connected: ${socket.id}`
  );

  socket.on("disconnect", (reason) => {
    console.log(
      `Socket client disconnected: ${socket.id} (${reason})`
    );
  });
});

/**
 * --------------------------------------------------------------------------
 * 404
 * --------------------------------------------------------------------------
 */

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Route not found.",
    path: req.originalUrl,
  });
});

/**
 * --------------------------------------------------------------------------
 * Error handler
 * --------------------------------------------------------------------------
 */

app.use((error, req, res, next) => {
  console.error(
    "Unhandled server error:",
    error
  );

  res.status(500).json({
    success: false,
    message: "Internal server error.",
  });
});

/**
 * --------------------------------------------------------------------------
 * Start
 * --------------------------------------------------------------------------
 */

httpServer.listen(PORT, () => {
  console.log("");
  console.log(
    "=============================================="
  );
  console.log(
    " Zero-Trust Threat Detection Backend"
  );
  console.log(
    "=============================================="
  );
  console.log(
    `Server:    http://127.0.0.1:${PORT}`
  );
  console.log(
    `Health:    http://127.0.0.1:${PORT}/api/health`
  );
  console.log(
    `Alerts:    http://127.0.0.1:${PORT}/api/alerts`
  );
  console.log(
    `Telemetry: http://127.0.0.1:${PORT}/api/telemetry/devices`
  );
  console.log(
    `Incidents: http://127.0.0.1:${PORT}/api/incidents`
  );
  console.log(
    `Responses: http://127.0.0.1:${PORT}/api/responses`
  );
  console.log(
    `Simulator: http://127.0.0.1:${PORT}/api/simulator/scenario`
  );
  console.log(
    "Storage:   IN-MEMORY"
  );
  console.log(
    "=============================================="
  );
  console.log("");
});