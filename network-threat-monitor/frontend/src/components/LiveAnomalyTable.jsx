import React, {
  useMemo,
} from "react";

const severityRank = {
  NORMAL: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

const severityStyles = {
  NORMAL:
    "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",

  LOW:
    "border-cyan-500/30 bg-cyan-500/10 text-cyan-400",

  MEDIUM:
    "border-yellow-500/30 bg-yellow-500/10 text-yellow-400",

  HIGH:
    "border-orange-500/30 bg-orange-500/10 text-orange-400",

  CRITICAL:
    "border-red-500/30 bg-red-500/10 text-red-400",
};

const formatTime = (value) => {
  if (!value) {
    return "--";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "--";
  }

  return date.toLocaleTimeString();
};

const formatBytes = (value) => {
  const bytes = Number(value) || 0;

  if (bytes >= 1024 * 1024 * 1024) {
    return `${(
      bytes /
      (1024 * 1024 * 1024)
    ).toFixed(2)} GB`;
  }

  if (bytes >= 1024 * 1024) {
    return `${(
      bytes /
      (1024 * 1024)
    ).toFixed(2)} MB`;
  }

  if (bytes >= 1024) {
    return `${(
      bytes / 1024
    ).toFixed(1)} KB`;
  }

  return `${bytes.toFixed(0)} B`;
};

const normalizeSeverity = (
  alert
) => {
  const explicit =
    String(
      alert?.severity ||
        ""
    )
      .trim()
      .toUpperCase();

  if (
    severityStyles[explicit]
  ) {
    return explicit;
  }

  const score =
    Number(
      alert?.threat_score
    ) || 0;

  if (score >= 90) {
    return "CRITICAL";
  }

  if (score >= 75) {
    return "HIGH";
  }

  if (score >= 50) {
    return "MEDIUM";
  }

  if (score >= 25) {
    return "LOW";
  }

  return "NORMAL";
};

const getSource = (alert) =>
  alert?.src_ip ||
  alert?.source_ip ||
  alert?.source ||
  "--";

const getDestination = (alert) =>
  alert?.dst_ip ||
  alert?.destination_ip ||
  alert?.destination ||
  "--";

const getProtocol = (alert) =>
  String(
    alert?.protocol ||
      "UNKNOWN"
  ).toUpperCase();

const getAction = (alert) =>
  alert?.suggested_action ||
  alert?.action ||
  "MONITOR";

const getBytes = (alert) =>
  Number(
    alert?.byte_count ??
      alert?.bytes ??
      alert?.total_bytes ??
      alert?.traffic_bytes ??
      0
  ) || 0;

const getTimestamp = (alert) =>
  alert?.timestamp ||
  alert?.created_at ||
  alert?.received_at ||
  null;

const LiveAnomalyTable = ({
  alerts = [],
}) => {
  const groupedThreats =
    useMemo(() => {
      const groups = new Map();

      for (
        const alert of alerts
      ) {
        if (!alert) {
          continue;
        }

        const src =
          getSource(alert);

        const dst =
          getDestination(alert);

        const protocol =
          getProtocol(alert);

        const action =
          String(
            getAction(alert)
          )
            .trim()
            .toUpperCase();

        /*
         * Correlation key:
         *
         * Same source + destination + protocol + action
         * becomes one visible threat group.
         */
        const key = [
          src,
          dst,
          protocol,
          action,
        ].join("|");

        const timestamp =
          getTimestamp(alert);

        const score =
          Number(
            alert.threat_score
          ) || 0;

        const bytes =
          getBytes(alert);

        const severity =
          normalizeSeverity(
            alert
          );

        if (
          !groups.has(key)
        ) {
          groups.set(key, {
            key,

            source: src,

            destination: dst,

            protocol,

            action,

            occurrences: 1,

            maxThreatScore: score,

            latestThreatScore:
              score,

            totalBytes: bytes,

            latestTimestamp:
              timestamp,

            severity,

            anomalyFlag:
              Boolean(
                alert.anomaly_flag
              ),

            latestAlert:
              alert,
          });

          continue;
        }

        const group =
          groups.get(key);

        group.occurrences += 1;

        group.totalBytes += bytes;

        group.maxThreatScore =
          Math.max(
            group.maxThreatScore,
            score
          );

        group.latestThreatScore =
          score;

        if (
          (
            severityRank[
              severity
            ] || 0
          ) >
          (
            severityRank[
              group.severity
            ] || 0
          )
        ) {
          group.severity =
            severity;
        }

        group.anomalyFlag =
          group.anomalyFlag ||
          Boolean(
            alert.anomaly_flag
          );

        const existingTime =
          group.latestTimestamp
            ? new Date(
                group.latestTimestamp
              ).getTime()
            : 0;

        const incomingTime =
          timestamp
            ? new Date(
                timestamp
              ).getTime()
            : 0;

        if (
          incomingTime >=
          existingTime
        ) {
          group.latestTimestamp =
            timestamp;

          group.latestAlert =
            alert;
        }
      }

      return Array.from(
        groups.values()
      )
        .sort(
          (a, b) => {
            const scoreDifference =
              b.maxThreatScore -
              a.maxThreatScore;

            if (
              scoreDifference !== 0
            ) {
              return scoreDifference;
            }

            const bTime =
              b.latestTimestamp
                ? new Date(
                    b.latestTimestamp
                  ).getTime()
                : 0;

            const aTime =
              a.latestTimestamp
                ? new Date(
                    a.latestTimestamp
                  ).getTime()
                : 0;

            return (
              bTime - aTime
            );
          }
        )
        .slice(0, 30);
    }, [alerts]);

  const totalOccurrences =
    groupedThreats.reduce(
      (
        total,
        threat
      ) =>
        total +
        threat.occurrences,
      0
    );

  return (
    <section className="rounded-xl border border-slate-800 bg-slate-950/80 p-6">
      {/* ============================================================= */}
      {/* Header                                                        */}
      {/* ============================================================= */}

      <div className="mb-5 flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-slate-100">
            Live Threat Events
          </h2>

          <p className="mt-1 text-xs uppercase tracking-widest text-slate-500">
            Correlated real-time network activity
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          <span className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 px-3 py-2 text-xs text-cyan-300">
            {groupedThreats.length}
            {" "}
            threat groups
          </span>

          <span className="rounded-lg border border-orange-500/20 bg-orange-500/5 px-3 py-2 text-xs text-orange-300">
            {totalOccurrences}
            {" "}
            observations
          </span>
        </div>
      </div>

      {/* ============================================================= */}
      {/* Empty state                                                    */}
      {/* ============================================================= */}

      {groupedThreats.length ===
      0 ? (
        <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 py-12 text-center">
          <div className="text-3xl text-emerald-400">
            ✓
          </div>

          <p className="mt-3 text-sm font-medium text-emerald-400">
            No active network anomalies
          </p>

          <p className="mt-1 text-xs text-slate-500">
            Correlated threats will appear
            here when detected.
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-[1100px] w-full border-collapse">
            <thead>
              <tr className="border-b border-slate-800">
                <th className="px-3 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  Last Seen
                </th>

                <th className="px-3 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  Source
                </th>

                <th className="px-3 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  Destination
                </th>

                <th className="px-3 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  Protocol
                </th>

                <th className="px-3 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  Traffic
                </th>

                <th className="px-3 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  Threat Score
                </th>

                <th className="px-3 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  Severity
                </th>

                <th className="px-3 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  Detection
                </th>

                <th className="px-3 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  Action
                </th>
              </tr>
            </thead>

            <tbody>
              {groupedThreats.map(
                (threat) => {
                  const severity =
                    threat.severity;

                  return (
                    <tr
                      key={
                        threat.key
                      }
                      className="border-b border-slate-900/80 transition hover:bg-slate-900/60"
                    >
                      {/* Timestamp */}

                      <td className="px-3 py-4 text-xs text-slate-500">
                        {formatTime(
                          threat.latestTimestamp
                        )}
                      </td>

                      {/* Source */}

                      <td className="px-3 py-4">
                        <div className="font-mono text-xs font-semibold text-cyan-300">
                          {
                            threat.source
                          }
                        </div>

                        {threat.occurrences >
                          1 && (
                          <div className="mt-1 text-[10px] text-slate-600">
                            {
                              threat.occurrences
                            }{" "}
                            observations
                          </div>
                        )}
                      </td>

                      {/* Destination */}

                      <td className="px-3 py-4 font-mono text-xs text-slate-300">
                        {
                          threat.destination
                        }
                      </td>

                      {/* Protocol */}

                      <td className="px-3 py-4">
                        <span className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] font-semibold text-slate-300">
                          {
                            threat.protocol
                          }
                        </span>
                      </td>

                      {/* Traffic */}

                      <td className="px-3 py-4">
                        <div className="font-mono text-xs text-slate-300">
                          {formatBytes(
                            threat.totalBytes
                          )}
                        </div>

                        {threat.occurrences >
                          1 && (
                          <div className="mt-1 text-[10px] text-slate-600">
                            aggregated
                          </div>
                        )}
                      </td>

                      {/* Threat score */}

                      <td className="px-3 py-4">
                        <div className="flex items-center gap-2">
                          <div className="h-2 w-16 overflow-hidden rounded-full bg-slate-800">
                            <div
                              className="h-full rounded-full bg-cyan-400"
                              style={{
                                width: `${Math.min(
                                  100,
                                  Math.max(
                                    0,
                                    threat.maxThreatScore
                                  )
                                )}%`,
                              }}
                            />
                          </div>

                          <span className="font-mono text-xs font-semibold text-slate-200">
                            {threat.maxThreatScore.toFixed(
                              0
                            )}
                          </span>
                        </div>
                      </td>

                      {/* Severity */}

                      <td className="px-3 py-4">
                        <span
                          className={`rounded-md border px-2 py-1 text-[10px] font-bold uppercase tracking-wider ${
                            severityStyles[
                              severity
                            ]
                          }`}
                        >
                          {severity}
                        </span>
                      </td>

                      {/* Detection */}

                      <td className="px-3 py-4">
                        {threat.anomalyFlag ? (
                          <span className="inline-flex items-center gap-2 text-xs font-semibold text-red-400">
                            <span className="h-2 w-2 rounded-full bg-red-400" />
                            ANOMALY
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-2 text-xs font-semibold text-slate-500">
                            <span className="h-2 w-2 rounded-full bg-slate-600" />
                            OBSERVED
                          </span>
                        )}
                      </td>

                      {/* Action */}

                      <td className="px-3 py-4">
                        <span className="rounded-md border border-red-500/20 bg-red-500/5 px-2 py-1 text-[10px] font-semibold text-red-300">
                          {
                            threat.action
                          }
                        </span>
                      </td>
                    </tr>
                  );
                }
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* ============================================================= */}
      {/* Footer                                                        */}
      {/* ============================================================= */}

      {groupedThreats.length >
        0 && (
        <div className="mt-4 flex flex-wrap justify-between gap-2 text-[10px] text-slate-600">
          <span>
            Repeated matching events are
            grouped automatically.
          </span>

          <span>
            Showing highest-risk groups first.
          </span>
        </div>
      )}
    </section>
  );
};

export default LiveAnomalyTable;