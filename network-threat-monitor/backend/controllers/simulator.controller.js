const ALLOWED_SCENARIOS = new Set([
  "normal_web",
  "normal_dns",
  "normal_api",
  "traffic_burst",
  "destination_sweep",
  "connection_flood",
  "data_exfiltration",
]);

const triggerScenario = (req, res) => {
  try {
    console.log(
      "SIMULATOR REQUEST BODY:",
      req.body
    );

    const scenario =
      req.body?.scenario;

    console.log(
      "SIMULATOR SCENARIO:",
      scenario
    );

    if (!scenario) {
      return res.status(400).json({
        success: false,
        message: "scenario is required.",
      });
    }

    if (!ALLOWED_SCENARIOS.has(scenario)) {
      return res.status(400).json({
        success: false,
        message:
          `Unsupported scenario: ${scenario}`,
      });
    }

    const io = req.app.get("io");

    if (!io) {
      console.error(
        "Socket.io instance not available."
      );

      return res.status(500).json({
        success: false,
        message:
          "Socket.io is not initialized.",
      });
    }

    const command = {
      scenario,
      timestamp:
        new Date().toISOString(),
    };

    io.emit(
      "simulation_scenario",
      command
    );

    console.log(
      "SIMULATION COMMAND BROADCAST:",
      command
    );

    return res.status(202).json({
      success: true,
      message:
        `Simulation scenario "${scenario}" requested.`,
      data: command,
    });
  } catch (error) {
    console.error(
      "Simulator controller error:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Internal server error.",
    });
  }
};

module.exports = {
  triggerScenario,
};