import {
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import { getAlertSocket } from "../services/alertSocket";

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

const MAX_ALERTS = 500;

const normalizeAlert = (alert) => {
  if (!alert || typeof alert !== "object") {
    return null;
  }

  const normalized = {};

  for (const field of CONTRACT_FIELDS) {
    if (
      Object.prototype.hasOwnProperty.call(
        alert,
        field
      )
    ) {
      normalized[field] = alert[field];
    }
  }

  return normalized;
};

const alertKey = (alert) =>
  [
    alert.timestamp,
    alert.src_ip,
    alert.dst_ip,
    alert.protocol,
    alert.byte_count,
    alert.threat_score,
    alert.anomaly_flag,
    alert.suggested_action,
  ].join("|");

export const useAlerts = () => {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const keysRef = useRef(new Set());

  const appendAlert = useCallback((incomingAlert) => {
    const alert = normalizeAlert(incomingAlert);

    if (!alert) {
      return;
    }

    const key = alertKey(alert);

    if (keysRef.current.has(key)) {
      return;
    }

    keysRef.current.add(key);

    setAlerts((currentAlerts) => {
      const nextAlerts = [
        alert,
        ...currentAlerts,
      ];

      return nextAlerts.slice(0, MAX_ALERTS);
    });
  }, []);

  /*
   * Initial alert history.
   *
   * IMPORTANT:
   * This is intentionally relative:
   *
   *     /api/alerts
   *
   * Vite proxies it to:
   *
   *     http://127.0.0.1:5000/api/alerts
   */
  useEffect(() => {
    let cancelled = false;

    const loadAlerts = async () => {
      try {
        setLoading(true);
        setError(null);

        const response = await fetch(
          "/api/alerts"
        );

        if (!response.ok) {
          throw new Error(
            `Backend returned HTTP ${response.status}`
          );
        }

        const result = await response.json();

        const serverAlerts =
          Array.isArray(result)
            ? result
            : Array.isArray(result.data)
              ? result.data
              : [];

        if (cancelled) {
          return;
        }

        const normalizedAlerts = [];
        const keys = new Set();

        for (const rawAlert of serverAlerts) {
          const alert =
            normalizeAlert(rawAlert);

          if (!alert) {
            continue;
          }

          const key = alertKey(alert);

          if (keys.has(key)) {
            continue;
          }

          keys.add(key);
          normalizedAlerts.push(alert);
        }

        keysRef.current = keys;

        setAlerts(
          normalizedAlerts.slice(
            0,
            MAX_ALERTS
          )
        );
      } catch (fetchError) {
        if (!cancelled) {
          console.error(
            "Failed to load alerts:",
            fetchError
          );

          setError(
            fetchError.message ||
              "Unable to load alerts."
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    loadAlerts();

    return () => {
      cancelled = true;
    };
  }, []);

  /*
   * Real-time Socket.io alerts.
   */
  useEffect(() => {
    const socket = getAlertSocket();

    const handleNewAlert = (incomingAlert) => {
      appendAlert(incomingAlert);
    };

    socket.on(
      "new_alert",
      handleNewAlert
    );

    return () => {
      socket.off(
        "new_alert",
        handleNewAlert
      );
    };
  }, [appendAlert]);

  return {
    alerts,
    loading,
    error,
  };
};

export default useAlerts;