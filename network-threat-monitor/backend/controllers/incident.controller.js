/**
 * incident.controller.js
 *
 * Incident intelligence layer.
 *
 * Responsibilities:
 *   - create incidents
 *   - correlate repeated observations
 *   - maintain occurrence_count
 *   - maintain first_seen / last_seen
 *   - maintain timeline
 *   - acknowledge incidents
 *   - expose incidents to the SOC dashboard
 *
 * This is intentionally in-memory for the current project stage.
 * MongoDB is not required.
 */

const incidents = [];

const MAX_INCIDENTS = 500;

/**
 * How long two matching detections can be considered
 * the same active incident.
 */
const CORRELATION_WINDOW_MS = 60 * 1000;

/**
 * Generate a unique incident ID.
 */
const generateIncidentId = () => {
  return `INC-${Date.now()}-${Math.floor(
    Math.random() * 10000
  )}`;
};

/**
 * Normalize a string.
 */
const normalize = (value) => {
  return String(value || "")
    .trim()
    .toUpperCase();
};

/**
 * Build the correlation key.
 *
 * We intentionally correlate on:
 *
 *   device
 *   source
 *   attack type
 *   suggested action
 *
 * This means repeated observations from the same endpoint
 * become one incident instead of dozens of cards.
 */
const buildCorrelationKey = ({
  device_id,
  src_ip,
  attack_type,
  suggested_action,
}) => {
  return [
    normalize(device_id),
    normalize(src_ip),
    normalize(attack_type || "UNKNOWN"),
    normalize(suggested_action),
  ].join("|");
};

/**
 * Find an active correlated incident.
 */
const findCorrelatedIncident = ({
  device_id,
  src_ip,
  attack_type,
  suggested_action,
}) => {
  const now = Date.now();

  const key = buildCorrelationKey({
    device_id,
    src_ip,
    attack_type,
    suggested_action,
  });

  return incidents.find((incident) => {
    if (
      incident.correlation_key !== key
    ) {
      return false;
    }

    const lastSeen = new Date(
      incident.last_seen
    ).getTime();

    if (Number.isNaN(lastSeen)) {
      return false;
    }

    return (
      now - lastSeen
      <= CORRELATION_WINDOW_MS
    );
  });
};

/**
 * Merge reasons without duplicates.
 */
const mergeReasons = (
  existing = [],
  incoming = []
) => {
  const merged = [
    ...existing,
  ];

  for (const reason of incoming) {
    if (
      reason &&
      !merged.includes(reason)
    ) {
      merged.push(reason);
    }
  }

  return merged;
};

/**
 * POST /api/incidents
 *
 * Creates or correlates an incident.
 */
const createIncident = async (
  req,
  res
) => {
  try {
    const {
      device_id,
      hostname,
      src_ip,
      risk_score,
      severity,
      suggested_action,
      reasons,
      attack_type,
    } = req.body || {};

    if (
      !device_id ||
      !src_ip ||
      risk_score === undefined ||
      !severity ||
      !suggested_action
    ) {
      return res.status(400).json({
        success: false,
        message:
          "device_id, src_ip, risk_score, severity and suggested_action are required.",
      });
    }

    const now =
      new Date().toISOString();

    const numericRisk =
      Number(risk_score);

    const normalizedRisk =
      Number.isFinite(numericRisk)
        ? Math.max(
            0,
            Math.min(
              100,
              numericRisk
            )
          )
        : 0;

    const normalizedReasons =
      Array.isArray(reasons)
        ? reasons.filter(Boolean)
        : [];

    const normalizedAttackType =
      attack_type ||
      "UNKNOWN";

    // -------------------------------------------------------------
    // Check whether this belongs to an existing incident.
    // -------------------------------------------------------------

    const existing =
      findCorrelatedIncident({
        device_id,
        src_ip,
        attack_type:
          normalizedAttackType,
        suggested_action,
      });

    if (existing) {
      existing.occurrence_count += 1;

      existing.last_seen = now;
      existing.updated_at = now;


      existing.risk_score = Math.max(
        Number(existing.risk_score) || 0,
        normalizedRisk
      );

      // Escalate severity when a later observation is more severe.
      const severityRank = {
        NORMAL: 0,
        LOW: 1,
        MEDIUM: 2,
        HIGH: 3,
        CRITICAL: 4,
      };

      if (
        (severityRank[
          normalize(severity)
        ] || 0) >
        (severityRank[
          normalize(existing.severity)
        ] || 0)
      ) {
        existing.severity =
          severity;
      }

      existing.reasons =
        mergeReasons(
          existing.reasons,
          normalizedReasons
        );

      existing.timeline.push({
        timestamp: now,
        event:
          "THREAT_REPEATED",
        occurrence_count:
          existing.occurrence_count,
        risk_score:
          normalizedRisk,
      });

      // Keep timeline bounded.
      if (
        existing.timeline.length >
        100
      ) {
        existing.timeline =
          existing.timeline.slice(
            -100
          );
      }

      const io =
        req.app.get("io");

      if (io) {
        io.emit(
          "incident_updated",
          existing
        );
      }

      return res.status(200).json({
        success: true,
        correlated: true,
        data: existing,
      });
    }

    // -------------------------------------------------------------
    // Create a new incident.
    // -------------------------------------------------------------

    const incident = {
      incident_id:
        generateIncidentId(),

      correlation_key:
        buildCorrelationKey({
          device_id,
          src_ip,
          attack_type:
            normalizedAttackType,
          suggested_action,
        }),

      device_id,

      hostname:
        hostname || device_id,

      src_ip,

      severity,

      risk_score:
        normalizedRisk,

      status: "OPEN",

      suggested_action,

      attack_type:
        normalizedAttackType,

      occurrence_count: 1,

      first_seen: now,

      last_seen: now,

      created_at: now,

      updated_at: now,

      reasons:
        normalizedReasons,

      timeline: [
        {
          timestamp: now,
          event:
            "INCIDENT_CREATED",
          occurrence_count: 1,
          risk_score:
            normalizedRisk,
        },
      ],
    };

    incidents.unshift(
      incident
    );

    if (
      incidents.length >
      MAX_INCIDENTS
    ) {
      incidents.length =
        MAX_INCIDENTS;
    }

    const io =
      req.app.get("io");

    if (io) {
      io.emit(
        "new_incident",
        incident
      );
    }

    return res.status(201).json({
      success: true,
      correlated: false,
      data: incident,
    });
  } catch (error) {
    console.error(
      "Incident creation failed:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Failed to create incident.",
    });
  }
};

/**
 * GET /api/incidents
 *
 * Returns incidents sorted newest first.
 */
const getIncidents = async (
  req,
  res
) => {
  try {
    const data =
      incidents
        .slice()
        .sort(
          (a, b) =>
            new Date(
              b.last_seen
            ).getTime() -
            new Date(
              a.last_seen
            ).getTime()
        );

    return res.status(200).json({
      success: true,
      data,
    });
  } catch (error) {
    console.error(
      "Failed to retrieve incidents:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Failed to retrieve incidents.",
    });
  }
};

/**
 * POST /api/incidents/:incidentId/acknowledge
 */
const acknowledgeIncident = async (
  req,
  res
) => {
  try {
    const incident =
      incidents.find(
        (item) =>
          item.incident_id ===
          req.params.incidentId
      );

    if (!incident) {
      return res.status(404).json({
        success: false,
        message:
          "Incident not found.",
      });
    }

    const now =
      new Date().toISOString();

    incident.status =
      "ACKNOWLEDGED";

    incident.updated_at = now;

    incident.timeline.push({
      timestamp: now,
      event:
        "INCIDENT_ACKNOWLEDGED",
    });

    const io =
      req.app.get("io");

    if (io) {
      io.emit(
        "incident_updated",
        incident
      );
    }

    return res.status(200).json({
      success: true,
      data: incident,
    });
  } catch (error) {
    console.error(
      "Incident acknowledgement failed:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Failed to acknowledge incident.",
    });
  }
};

/**
 * Generic timeline append helper.
 */
const appendIncidentTimeline = (
  incidentId,
  event
) => {
  const incident =
    incidents.find(
      (item) =>
        item.incident_id ===
        incidentId
    );

  if (!incident) {
    return null;
  }

  const timelineEvent = {
    timestamp:
      new Date().toISOString(),
    ...event,
  };

  incident.timeline.push(
    timelineEvent
  );

  incident.updated_at =
    timelineEvent.timestamp;

  return incident;
};

/**
 * Generic status helper.
 */
const updateIncidentStatus = (
  incidentId,
  status
) => {
  const incident =
    incidents.find(
      (item) =>
        item.incident_id ===
        incidentId
    );

  if (!incident) {
    return null;
  }

  incident.status = status;

  incident.updated_at =
    new Date().toISOString();

  return incident;
};

module.exports = {
  createIncident,
  getIncidents,
  acknowledgeIncident,
  appendIncidentTimeline,
  updateIncidentStatus,
};