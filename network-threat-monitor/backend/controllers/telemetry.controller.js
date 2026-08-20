/**
 * telemetry.controller.js
 *
 * Maintains the latest telemetry state for every unique device.
 *
 * One device can send many telemetry windows.
 * The registry stores only the latest state for dashboard purposes.
 */

const deviceRegistry = new Map();

const MAX_DEVICES = 1000;

const normalizeNumber = (value) => {
  const number = Number(value);
  return Number.isFinite(number)
    ? number
    : 0;
};

const normalizeTelemetry = (body) => {
  return {
    device_id: String(
      body.device_id || ""
    ).trim(),

    hostname: String(
      body.hostname || "Unknown device"
    ).trim(),

    src_ip: String(
      body.src_ip || ""
    ).trim(),

    timestamp:
      body.timestamp ||
      new Date().toISOString(),

    bytes_in: normalizeNumber(
      body.bytes_in
    ),

    bytes_out: normalizeNumber(
      body.bytes_out
    ),

    interval_seconds:
      normalizeNumber(
        body.interval_seconds
      ),

    packets: normalizeNumber(
      body.packets
    ),

    unique_destinations:
      normalizeNumber(
        body.unique_destinations
      ),

    flows: normalizeNumber(
      body.flows
    ),

    bytes_per_second_in:
      normalizeNumber(
        body.bytes_per_second_in
      ),

    bytes_per_second_out:
      normalizeNumber(
        body.bytes_per_second_out
      ),

    total_bytes:
      normalizeNumber(
        body.total_bytes
      ),

    total_bytes_per_second:
      normalizeNumber(
        body.total_bytes_per_second
      ),
  };
};

/**
 * POST /api/telemetry
 */
const receiveTelemetry = async (
  req,
  res
) => {
  try {
    const telemetry =
      normalizeTelemetry(
        req.body || {}
      );

    if (
      !telemetry.device_id ||
      !telemetry.src_ip
    ) {
      return res.status(400).json({
        success: false,
        message:
          "device_id and src_ip are required.",
      });
    }

    const previous =
      deviceRegistry.get(
        telemetry.device_id
      );

    const now =
      new Date().toISOString();

    const device = {
      ...previous,
      ...telemetry,

      received_at: now,

      first_seen:
        previous?.first_seen ||
        telemetry.timestamp ||
        now,

      last_seen:
        telemetry.timestamp ||
        now,

      telemetry_count:
        (previous?.telemetry_count || 0) + 1,
    };

    deviceRegistry.set(
      telemetry.device_id,
      device
    );

    // Prevent unbounded memory growth.
    if (
      deviceRegistry.size >
      MAX_DEVICES
    ) {
      const oldestKey =
        deviceRegistry.keys().next().value;

      if (oldestKey) {
        deviceRegistry.delete(
          oldestKey
        );
      }
    }

    const io =
      req.app.get("io");

    if (io) {
      io.emit(
        "device_telemetry",
        device
      );
    }

    return res.status(201).json({
      success: true,
      data: device,
    });
  } catch (error) {
    console.error(
      "Telemetry ingestion failed:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Failed to process telemetry.",
    });
  }
};

/**
 * GET /api/telemetry/devices
 *
 * Returns one latest record per device.
 */
const getDevices = async (
  req,
  res
) => {
  try {
    const devices =
      Array.from(
        deviceRegistry.values()
      ).sort(
        (a, b) =>
          new Date(
            b.last_seen ||
              b.received_at
          ).getTime() -
          new Date(
            a.last_seen ||
              a.received_at
          ).getTime()
      );

    return res.status(200).json({
      success: true,
      data: devices,
    });
  } catch (error) {
    console.error(
      "Device registry retrieval failed:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Failed to retrieve device registry.",
    });
  }
};

module.exports = {
  receiveTelemetry,
  getDevices,
};