import React, {
  memo,
  useMemo,
  useState,
} from "react";

const severityStyles = {
  CRITICAL:
    "border-red-500/40 bg-red-500/10 text-red-400",

  HIGH:
    "border-orange-500/40 bg-orange-500/10 text-orange-400",

  MEDIUM:
    "border-yellow-500/40 bg-yellow-500/10 text-yellow-400",

  LOW:
    "border-cyan-500/40 bg-cyan-500/10 text-cyan-400",

  NORMAL:
    "border-emerald-500/40 bg-emerald-500/10 text-emerald-400",
};

const statusStyles = {
  OPEN:
    "border-red-500/30 bg-red-500/10 text-red-400",

  ACKNOWLEDGED:
    "border-yellow-500/30 bg-yellow-500/10 text-yellow-400",

  RESOLVED:
    "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
};

const formatTime = (
  value
) => {
  if (!value) {
    return "--";
  }

  const date =
    new Date(value);

  if (
    Number.isNaN(
      date.getTime()
    )
  ) {
    return "--";
  }

  return date.toLocaleTimeString();
};

const formatDateTime = (
  value
) => {
  if (!value) {
    return "--";
  }

  const date =
    new Date(value);

  if (
    Number.isNaN(
      date.getTime()
    )
  ) {
    return "--";
  }

  return date.toLocaleString();
};

const IncidentCard = memo(
  ({
    incident,
    onAcknowledge,
    onExecuteResponse,
    acknowledging,
    executing,
    responseResult,
  }) => {
    const [
      expanded,
      setExpanded,
    ] = useState(false);

    const occurrenceCount =
      Number(
        incident.occurrence_count
      ) || 1;

    const riskScore =
      Number(
        incident.risk_score
      ) || 0;

    const severity =
      incident.severity ||
      "UNKNOWN";

    const status =
      incident.status ||
      "OPEN";

    const reasons =
      Array.isArray(
        incident.reasons
      )
        ? incident.reasons
        : [];

    const timeline =
      Array.isArray(
        incident.timeline
      )
        ? incident.timeline
        : [];

    return (
      <article className="rounded-xl border border-slate-800 bg-slate-950/80 p-5">
        {/* ============================================================= */}
        {/* Header                                                        */}
        {/* ============================================================= */}

        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`rounded-md border px-2 py-1 text-[10px] font-bold uppercase tracking-wider ${
                  severityStyles[
                    severity
                  ] ||
                  "border-slate-700 bg-slate-900 text-slate-400"
                }`}
              >
                {severity}
              </span>

              <span
                className={`rounded-md border px-2 py-1 text-[10px] font-bold uppercase tracking-wider ${
                  statusStyles[
                    status
                  ] ||
                  "border-slate-700 bg-slate-900 text-slate-400"
                }`}
              >
                {status}
              </span>
            </div>

            <h3 className="mt-3 text-base font-semibold text-slate-100">
              {incident.attack_type ||
                "Behavioral Anomaly"}
            </h3>

            <p className="mt-1 text-xs text-slate-500">
              {incident.incident_id}
            </p>
          </div>

          <div className="text-right">
            <div className="text-2xl font-bold text-red-400">
              {riskScore.toFixed(1)}
            </div>

            <div className="text-[10px] uppercase tracking-wider text-slate-500">
              Risk score
            </div>
          </div>
        </div>

        {/* ============================================================= */}
        {/* Device information                                             */}
        {/* ============================================================= */}

        <div className="mt-5 grid gap-3 md:grid-cols-4">
          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
            <div className="text-[10px] uppercase tracking-wider text-slate-500">
              Device
            </div>

            <div className="mt-1 text-sm font-medium text-cyan-300">
              {incident.hostname ||
                incident.device_id ||
                "--"}
            </div>
          </div>

          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
            <div className="text-[10px] uppercase tracking-wider text-slate-500">
              Source IP
            </div>

            <div className="mt-1 text-sm text-slate-200">
              {incident.src_ip ||
                "--"}
            </div>
          </div>

          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
            <div className="text-[10px] uppercase tracking-wider text-slate-500">
              Occurrences
            </div>

            <div className="mt-1 text-sm font-semibold text-orange-300">
              {occurrenceCount}
            </div>
          </div>

          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
            <div className="text-[10px] uppercase tracking-wider text-slate-500">
              Recommended action
            </div>

            <div className="mt-1 text-sm font-semibold text-slate-100">
              {incident.suggested_action ||
                "--"}
            </div>
          </div>
        </div>

        {/* ============================================================= */}
        {/* Time summary                                                   */}
        {/* ============================================================= */}

        <div className="mt-4 grid gap-3 md:grid-cols-2">
          <div className="rounded-lg border border-slate-900 bg-slate-950 p-3">
            <div className="text-[10px] uppercase tracking-wider text-slate-600">
              First seen
            </div>

            <div className="mt-1 text-xs text-slate-300">
              {formatDateTime(
                incident.first_seen
              )}
            </div>
          </div>

          <div className="rounded-lg border border-slate-900 bg-slate-950 p-3">
            <div className="text-[10px] uppercase tracking-wider text-slate-600">
              Last seen
            </div>

            <div className="mt-1 text-xs text-slate-300">
              {formatDateTime(
                incident.last_seen
              )}
            </div>
          </div>
        </div>

        {/* ============================================================= */}
        {/* Reasons                                                        */}
        {/* ============================================================= */}

        {reasons.length >
          0 && (
          <div className="mt-4">
            <div className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
              Why this was detected
            </div>

            <div className="space-y-2">
              {reasons.map(
                (
                  reason,
                  index
                ) => (
                  <div
                    key={`${incident.incident_id}-reason-${index}`}
                    className="rounded-lg border border-slate-900 bg-slate-950 px-3 py-2 text-xs text-slate-300"
                  >
                    <span className="mr-2 text-red-400">
                      •
                    </span>

                    {reason}
                  </div>
                )
              )}
            </div>
          </div>
        )}

        {/* ============================================================= */}
        {/* Expandable timeline                                            */}
        {/* ============================================================= */}

        <div className="mt-4">
          <button
            type="button"
            onClick={() =>
              setExpanded(
                (value) =>
                  !value
              )
            }
            className="text-xs font-medium text-cyan-400 hover:text-cyan-300"
          >
            {expanded
              ? "Hide timeline"
              : `Show timeline (${timeline.length})`}
          </button>

          {expanded && (
            <div className="mt-3 space-y-2">
              {timeline
                .slice()
                .reverse()
                .map(
                  (
                    event,
                    index
                  ) => (
                    <div
                      key={`${incident.incident_id}-timeline-${index}`}
                      className="rounded-lg border border-slate-900 bg-slate-950 p-3"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="text-xs font-medium text-slate-200">
                          {
                            event.event
                          }
                        </span>

                        <span className="text-[10px] text-slate-600">
                          {formatTime(
                            event.timestamp
                          )}
                        </span>
                      </div>

                      {event.occurrence_count && (
                        <div className="mt-1 text-[10px] text-slate-500">
                          Occurrence #
                          {
                            event.occurrence_count
                          }
                        </div>
                      )}
                    </div>
                  )
                )}
            </div>
          )}
        </div>

        {/* ============================================================= */}
        {/* Response result                                                */}
        {/* ============================================================= */}

        {responseResult && (
          <div className="mt-4 rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-3">
            <div className="text-[10px] uppercase tracking-wider text-cyan-500">
              Response status
            </div>

            <div className="mt-1 text-sm text-slate-200">
              {responseResult.status ||
                responseResult.action ||
                responseResult.message ||
                "Response processed"}
            </div>

            {responseResult.error && (
              <div className="mt-1 text-xs text-red-400">
                {responseResult.error}
              </div>
            )}
          </div>
        )}

        {/* ============================================================= */}
        {/* Actions                                                        */}
        {/* ============================================================= */}

        <div className="mt-5 flex flex-wrap gap-2">
          {status ===
            "OPEN" && (
            <button
              type="button"
              onClick={() =>
                onAcknowledge(
                  incident
                )
              }
              disabled={
                acknowledging
              }
              className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 px-3 py-2 text-xs font-semibold text-yellow-300 disabled:opacity-50"
            >
              {acknowledging
                ? "Acknowledging..."
                : "Acknowledge"}
            </button>
          )}

          <button
            type="button"
            onClick={() =>
              onExecuteResponse(
                incident
              )
            }
            disabled={
              executing
            }
            className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs font-semibold text-red-300 disabled:opacity-50"
          >
            {executing
              ? "Executing..."
              : incident.suggested_action ||
                "Execute Response"}
          </button>
        </div>
      </article>
    );
  }
);

const IncidentCenter = ({
  incidents = [],
}) => {
  const [
    executingIncident,
    setExecutingIncident,
  ] = useState(null);

  const [
    responseResults,
    setResponseResults,
  ] = useState({});

  const [
    acknowledgingIncident,
    setAcknowledgingIncident,
  ] = useState(null);

  const normalizedIncidents =
    useMemo(() => {
      const map =
        new Map();

      for (const incident of incidents) {
        if (!incident) {
          continue;
        }

        const key =
          incident.incident_id ||
          `${incident.device_id}-${incident.src_ip}`;

        if (!map.has(key)) {
          map.set(
            key,
            incident
          );
        }
      }

      return Array.from(
        map.values()
      ).sort(
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
    }, [
      incidents,
    ]);

  const openIncidentCount =
    normalizedIncidents.filter(
      (incident) =>
        (
          incident.status ||
          "OPEN"
        ) === "OPEN"
    ).length;

  const totalOccurrences =
    normalizedIncidents.reduce(
      (
        total,
        incident
      ) =>
        total +
        (
          Number(
            incident.occurrence_count
          ) || 1
        ),
      0
    );

  const averageRisk =
    normalizedIncidents.length >
    0
      ? normalizedIncidents.reduce(
          (
            total,
            incident
          ) =>
            total +
            (
              Number(
                incident.risk_score
              ) || 0
            ),
          0
        ) /
        normalizedIncidents.length
      : 0;

  /**
   * Execute simulated response.
   */
  const executeResponse =
    async (
      incident
    ) => {
      try {
        setExecutingIncident(
          incident.incident_id
        );

        const response =
          await fetch(
            "/api/responses/execute",
            {
              method: "POST",
              headers: {
                "Content-Type":
                  "application/json",
              },
              body:
                JSON.stringify({
                  incident_id:
                    incident.incident_id,

                  device_id:
                    incident.device_id,

                  action:
                    incident.suggested_action,
                }),
            }
          );

        const result =
          await response.json();

        if (!response.ok) {
          throw new Error(
            result.message ||
              "Response execution failed."
          );
        }

        setResponseResults(
          (current) => ({
            ...current,

            [incident.incident_id]:
              result.data,
          })
        );
      } catch (error) {
        console.error(
          "Response execution failed:",
          error
        );

        setResponseResults(
          (current) => ({
            ...current,

            [incident.incident_id]: {
              status:
                "FAILED",
              error:
                error.message,
            },
          })
        );
      } finally {
        setExecutingIncident(
          null
        );
      }
    };

  /**
   * Acknowledge incident.
   */
  const acknowledgeIncident =
    async (
      incident
    ) => {
      try {
        setAcknowledgingIncident(
          incident.incident_id
        );

        const response =
          await fetch(
            `/api/incidents/${encodeURIComponent(
              incident.incident_id
            )}/acknowledge`,
            {
              method: "POST",
            }
          );

        const result =
          await response.json();

        if (!response.ok) {
          throw new Error(
            result.message ||
              "Failed to acknowledge incident."
          );
        }
      } catch (error) {
        console.error(
          "Incident acknowledgement failed:",
          error
        );
      } finally {
        setAcknowledgingIncident(
          null
        );
      }
    };

  if (
    normalizedIncidents.length ===
    0
  ) {
    return (
      <section className="rounded-xl border border-slate-800 bg-slate-950/80 p-6">
        <div className="mb-5 flex flex-wrap items-end justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold text-slate-100">
              Incident Intelligence
            </h2>

            <p className="mt-1 text-xs uppercase tracking-widest text-slate-500">
              Correlated security events
            </p>
          </div>
        </div>

        <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 py-12 text-center">
          <div className="text-3xl text-emerald-400">
            ✓
          </div>

          <p className="mt-3 text-sm font-medium text-emerald-400">
            No active security incidents
          </p>

          <p className="mt-1 text-xs text-slate-500">
            The monitored environment is
            currently within the configured
            risk threshold.
          </p>
        </div>
      </section>
    );
  }

  return (
    <section className="rounded-xl border border-slate-800 bg-slate-950/80 p-6">
      {/* =============================================================== */}
      {/* Header                                                          */}
      {/* =============================================================== */}

      <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-slate-100">
            Incident Intelligence
          </h2>

          <p className="mt-1 text-xs uppercase tracking-widest text-slate-500">
            Correlated security events
          </p>
        </div>

        <div className="flex flex-wrap gap-2 text-xs">
          <span className="rounded-lg border border-red-500/20 bg-red-500/5 px-3 py-2 text-red-300">
            Open:{" "}
            {openIncidentCount}
          </span>

          <span className="rounded-lg border border-orange-500/20 bg-orange-500/5 px-3 py-2 text-orange-300">
            Occurrences:{" "}
            {totalOccurrences}
          </span>

          <span className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 px-3 py-2 text-cyan-300">
            Avg Risk:{" "}
            {averageRisk.toFixed(
              1
            )}
          </span>
        </div>
      </div>

      {/* =============================================================== */}
      {/* Incident list                                                    */}
      {/* =============================================================== */}

      <div className="space-y-5">
        {normalizedIncidents.map(
          (incident) => (
            <IncidentCard
              key={
                incident.incident_id
              }
              incident={
                incident
              }
              onAcknowledge={
                acknowledgeIncident
              }
              onExecuteResponse={
                executeResponse
              }
              acknowledging={
                acknowledgingIncident ===
                incident.incident_id
              }
              executing={
                executingIncident ===
                incident.incident_id
              }
              responseResult={
                responseResults[
                  incident.incident_id
                ]
              }
            />
          )
        )}
      </div>
    </section>
  );
};

export default memo(
  IncidentCenter
);