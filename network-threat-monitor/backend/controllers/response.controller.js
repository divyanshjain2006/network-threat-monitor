const responses = new Map();

const validActions = new Set([
  "ALLOW",
  "MONITOR",
  "REQUIRE_STEP_UP_AUTH",
  "BLOCK",
  "QUARANTINE_DEVICE",
]);

/**
 * POST /api/responses/execute
 *
 * Safe development implementation.
 * No real device/network change is performed.
 */
const executeResponse = async (req, res) => {
  try {
    const {
      incident_id,
      device_id,
      action,
    } = req.body;

    if (
      !incident_id ||
      !device_id ||
      !action
    ) {
      return res.status(400).json({
        success: false,
        message:
          "incident_id, device_id and action are required.",
      });
    }

    if (!validActions.has(action)) {
      return res.status(400).json({
        success: false,
        message:
          `Unsupported response action: ${action}`,
      });
    }

    const timestamp =
      new Date().toISOString();

    const response = {
      response_id: `RESP-${Date.now()}`,
      incident_id,
      device_id,
      action,
      mode: "SIMULATED",
      status: "EXECUTED",
      timestamp,
    };

    responses.set(
      response.response_id,
      response
    );

    /**
     * Update the matching incident.
     *
     * incident.controller.js currently stores incidents in memory,
     * so we expose a small internal helper from that module.
     */
    const {
      appendIncidentTimeline,
      updateIncidentStatus,
    } = require(
      "./incident.controller"
    );

    appendIncidentTimeline(
      incident_id,
      {
        timestamp,
        event: "RESPONSE_EXECUTED",
        action,
        mode: "SIMULATED",
      }
    );

    updateIncidentStatus(
      incident_id,
      "RESPONSE_EXECUTED"
    );

    const io = req.app.get("io");

    if (io) {
      io.emit(
        "response_executed",
        response
      );
    }

    return res.status(200).json({
      success: true,
      data: response,
    });
  } catch (error) {
    console.error(
      "Response execution failed:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Failed to execute response.",
    });
  }
};

const getResponses = async (
  req,
  res
) => {
  return res.status(200).json({
    success: true,
    data: Array.from(
      responses.values()
    ).reverse(),
  });
};

module.exports = {
  executeResponse,
  getResponses,
};