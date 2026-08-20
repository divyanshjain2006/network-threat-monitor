const express = require("express");

const {
  receiveTelemetry,
  getDevices,
} = require("../controllers/telemetry.controller");

const router = express.Router();

/**
 * POST /api/telemetry
 *
 * Receive telemetry from an edge agent.
 */
router.post(
  "/",
  receiveTelemetry
);

/**
 * GET /api/telemetry/devices
 *
 * Return the latest telemetry state
 * for every registered device.
 */
router.get(
  "/devices",
  getDevices
);

module.exports = router;