import { useCallback, useEffect, useRef, useState } from "react";
import { getAlertSocket } from "../services/alertSocket";

const BACKEND_URL =
  import.meta.env.VITE_BACKEND_URL || "http://localhost:5000";

const MAX_ALERTS = 500;

/**
 * Fields permitted by contract.json.
 */
const CONTRACT_FIELDS = [
  "timestamp",
  "src_ip",
  "dst_ip",
  "protocol",
  "byte_count",
  "threat_score",
  "anomaly_flag",
  "suggested_action",
];

/**
 * Keep only fields defined by contract.json.
 *
 * This prevents UI state from accidentally becoming a different
 * data contract if the backend later adds unrelated properties.
 */
const normalizeAlert = (alert) => {
  if (!alert || typeof alert !== "object") {
    return null;
  }

  const normalized = {};

  for (const field of CONTRACT_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(alert, field)) {
      normalized[field] = alert[field];
    }
  }

  return normalized;
};

/**
 * Creates a stable identifier for deduplication.
 *
 * The contract itself does not define an ID, so the identifier is generated
 * locally from the immutable alert fields.
 */
const createAlertKey = (alert) => {
  if (!alert) {
    return "";
  }

  return [
    alert.timestamp,
    alert.src_ip,
    alert.dst_ip,
    alert.protocol,
    alert.byte_count,
    alert.threat_score,
    alert.anomaly_flag,
    alert.suggested_action,
  ].join("|");
};

export const useAlerts = () => {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const alertKeysRef = useRef(new Set());

  /**
   * Add an alert without introducing duplicates.
   */
  const appendAlert = useCallback((incomingAlert) => {
    const normalizedAlert = normalizeAlert(incomingAlert);

    if (!normalizedAlert) {
      return;
    }

    const alertKey = createAlertKey(normalizedAlert);

    if (!alertKey || alertKeysRef.current.has(alertKey)) {
      return;
    }

    alertKeysRef.current.add(alertKey);

    setAlerts((currentAlerts) => {
      const nextAlerts = [normalizedAlert, ...currentAlerts];

      if (nextAlerts.length > MAX_ALERTS) {
        const removedAlerts = nextAlerts.slice(MAX_ALERTS);

        removedAlerts.forEach((alert) => {
          alertKeysRef.current.delete(createAlertKey(alert));
        });

        return nextAlerts.slice(0, MAX_ALERTS);
      }

      return nextAlerts;
    });
  }, []);

  /**
   * Load historical alerts from REST API.
   */
  useEffect(() => {
    let cancelled = false;

    const fetchAlerts = async () => {
      try {
        setLoading(true);
        setError(null);

        const response = await fetch(`${BACKEND_URL}/api/alerts`);

        if (!response.ok) {
          throw new Error(
            `Failed to fetch alerts: HTTP ${response.status}`
          );
        }

        const result = await response.json();

        /**
         * Supports:
         * { data: [...] }
         * or
         * [...]
         */
        const receivedAlerts = Array.isArray(result)
          ? result
          : Array.isArray(result.data)
            ? result.data
            : [];

        if (cancelled) {
          return;
        }

        const normalizedAlerts = [];
        const keys = new Set();

        for (const rawAlert of receivedAlerts) {
          const alert = normalizeAlert(rawAlert);

          if (!alert) {
            continue;
          }

          const key = createAlertKey(alert);

          if (!key || keys.has(key)) {
            continue;
          }

          keys.add(key);
          normalizedAlerts.push(alert);
        }

        alertKeysRef.current = keys;
        setAlerts(normalizedAlerts.slice(0, MAX_ALERTS));
      } catch (fetchError) {
        if (!cancelled) {
          console.error("Failed to load alerts:", fetchError);
          setError(fetchError.message || "Unable to load alerts.");
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    fetchAlerts();

    return () => {
      cancelled = true;
    };
  }, []);

  /**
   * Subscribe to real-time anomaly events.
   */
  useEffect(() => {
    const socket = getAlertSocket();

    const handleNewAlert = (incomingAlert) => {
      appendAlert(incomingAlert);
    };

    socket.on("new_alert", handleNewAlert);

    return () => {
      socket.off("new_alert", handleNewAlert);
    };
  }, [appendAlert]);

  return {
    alerts,
    loading,
    error,
    alertCount: alerts.length,
  };
};

export default useAlerts;