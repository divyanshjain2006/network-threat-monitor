import {
  useCallback,
  useEffect,
  useState,
} from "react";

const normalizeIncident = (incident) => {
  if (!incident) {
    return null;
  }

  return {
    ...incident,

    occurrence_count:
      Number(
        incident.occurrence_count
      ) || 1,

    risk_score:
      Number(
        incident.risk_score
      ) || 0,

    reasons: Array.isArray(
      incident.reasons
    )
      ? incident.reasons
      : [],

    timeline: Array.isArray(
      incident.timeline
    )
      ? incident.timeline
      : [],
  };
};

const sortIncidents = (items) => {
  return [...items].sort(
    (a, b) =>
      new Date(
        b.last_seen ||
          b.created_at
      ).getTime() -
      new Date(
        a.last_seen ||
          a.created_at
      ).getTime()
  );
};

export const useIncidents = ({
  socket = null,
} = {}) => {
  const [
    incidents,
    setIncidents,
  ] = useState([]);

  const [
    loading,
    setLoading,
  ] = useState(true);

  const [
    error,
    setError,
  ] = useState("");

  const loadIncidents =
    useCallback(async () => {
      try {
        setError("");

        const response =
          await fetch(
            "/api/incidents"
          );

        if (!response.ok) {
          throw new Error(
            `Incident request failed: ${response.status}`
          );
        }

        const result =
          await response.json();

        const rows =
          Array.isArray(
            result?.data
          )
            ? result.data
                .map(
                  normalizeIncident
                )
                .filter(Boolean)
            : [];

        setIncidents(
          sortIncidents(rows)
        );
      } catch (err) {
        console.error(
          "Failed to load incidents:",
          err
        );

        setError(
          err.message ||
            "Failed to load incidents."
        );
      } finally {
        setLoading(false);
      }
    }, []);

  useEffect(() => {
    loadIncidents();

    const interval =
      setInterval(
        loadIncidents,
        5000
      );

    return () => {
      clearInterval(
        interval
      );
    };
  }, [loadIncidents]);

  useEffect(() => {
    if (!socket) {
      return undefined;
    }

    const handleNewIncident =
      (incident) => {
        const normalized =
          normalizeIncident(
            incident
          );

        if (!normalized) {
          return;
        }

        setIncidents(
          (current) =>
            sortIncidents([
              normalized,
              ...current.filter(
                (item) =>
                  item.incident_id !==
                  normalized.incident_id
              ),
            ])
        );
      };

    const handleIncidentUpdated =
      (incident) => {
        const normalized =
          normalizeIncident(
            incident
          );

        if (!normalized) {
          return;
        }

        setIncidents(
          (current) => {
            const exists =
              current.some(
                (item) =>
                  item.incident_id ===
                  normalized.incident_id
              );

            if (!exists) {
              return sortIncidents([
                normalized,
                ...current,
              ]);
            }

            return sortIncidents(
              current.map(
                (item) =>
                  item.incident_id ===
                  normalized.incident_id
                    ? normalized
                    : item
              )
            );
          }
        );
      };

    socket.on(
      "new_incident",
      handleNewIncident
    );

    socket.on(
      "incident_updated",
      handleIncidentUpdated
    );

    return () => {
      socket.off(
        "new_incident",
        handleNewIncident
      );

      socket.off(
        "incident_updated",
        handleIncidentUpdated
      );
    };
  }, [socket]);

  return {
    incidents,
    loading,
    error,
    refresh:
      loadIncidents,
  };
};

export default useIncidents;