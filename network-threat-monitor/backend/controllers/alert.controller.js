const alerts = [];

const MAX_ALERTS = 500;

/**
 * POST /api/alerts
 *
 * Receives an alert from the local edge agent.
 * Stores it in memory and broadcasts it through Socket.io.
 */
const createAlert = async (req, res) => {
  try {
    const alert = req.body;

    if (!alert || typeof alert !== "object") {
      return res.status(400).json({
        success: false,
        message: "Alert payload must be a JSON object.",
      });
    }

    const requiredFields = [
      "timestamp",
      "src_ip",
      "dst_ip",
      "protocol",
      "byte_count",
      "threat_score",
      "anomaly_flag",
      "suggested_action",
    ];

    const missingFields = requiredFields.filter(
      (field) => !(field in alert)
    );

    if (missingFields.length > 0) {
      return res.status(400).json({
        success: false,
        message: "Alert is missing required fields.",
        missingFields,
      });
    }

    const storedAlert = {
      timestamp: alert.timestamp,
      src_ip: alert.src_ip,
      dst_ip: alert.dst_ip,
      protocol: alert.protocol,
      byte_count: alert.byte_count,
      threat_score: alert.threat_score,
      anomaly_flag: alert.anomaly_flag,
      suggested_action: alert.suggested_action,
    };

    alerts.unshift(storedAlert);

    if (alerts.length > MAX_ALERTS) {
      alerts.length = MAX_ALERTS;
    }

    const io = req.app.get("io");

    if (io) {
      io.emit("new_alert", storedAlert);
    }

    return res.status(201).json({
      success: true,
      message: "Alert received successfully.",
      data: storedAlert,
    });
  } catch (error) {
    console.error("Alert creation failed:", error);

    return res.status(500).json({
      success: false,
      message: "Internal server error.",
    });
  }
};

/**
 * GET /api/alerts
 *
 * Returns the most recently received alerts.
 */
const getAlerts = async (req, res) => {
  return res.status(200).json({
    success: true,
    data: alerts,
  });
};

module.exports = {
  createAlert,
  getAlerts,
};