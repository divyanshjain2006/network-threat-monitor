import React, { memo, useMemo } from "react";

/**
 * UI-only severity classification.
 *
 * These bands are NOT part of contract.json.
 * They are only used to make the SOC dashboard easier to read.
 */
const getSeverity = (score) => {
  if (score >= 80) {
    return {
      label: "CRITICAL",
      classes:
        "border-red-500/30 bg-red-500/10 text-red-400 shadow-red-500/10",
    };
  }

  if (score >= 60) {
    return {
      label: "HIGH",
      classes:
        "border-orange-500/30 bg-orange-500/10 text-orange-400",
    };
  }

  if (score >= 30) {
    return {
      label: "MEDIUM",
      classes:
        "border-yellow-500/30 bg-yellow-500/10 text-yellow-400",
    };
  }

  return {
    label: "LOW",
    classes:
      "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
  };
};

const formatTimestamp = (timestamp) => {
  const date = new Date(timestamp);

  if (Number.isNaN(date.getTime())) {
    return timestamp;
  }

  return date.toLocaleString();
};

const formatBytes = (bytes) => {
  if (bytes < 1024) {
    return `${bytes} B`;
  }

  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }

  if (bytes < 1024 * 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
};

const LiveAnomalyRow = memo(({ alert }) => {
  const severity = getSeverity(alert.threat_score);

  return (
    <tr className="border-b border-slate-800/70 transition-colors hover:bg-slate-800/40">
      <td className="whitespace-nowrap px-4 py-4 text-sm text-slate-400">
        {formatTimestamp(alert.timestamp)}
      </td>

      <td className="px-4 py-4">
        <div className="font-mono text-sm text-cyan-300">
          {alert.src_ip}
        </div>
      </td>

      <td className="px-4 py-4">
        <div className="font-mono text-sm text-purple-300">
          {alert.dst_ip}
        </div>
      </td>

      <td className="px-4 py-4">
        <span className="rounded-md border border-slate-700 bg-slate-800 px-2 py-1 font-mono text-xs text-slate-300">
          {alert.protocol}
        </span>
      </td>

      <td className="px-4 py-4 text-right font-mono text-sm text-slate-300">
        {formatBytes(alert.byte_count)}
      </td>

      <td className="px-4 py-4">
        <div className="flex items-center gap-3">
          <div className="h-2 w-24 overflow-hidden rounded-full bg-slate-800">
            <div
              className="h-full rounded-full bg-cyan-400 transition-all duration-500"
              style={{
                width: `${Math.min(
                  Math.max(alert.threat_score, 0),
                  100
                )}%`,
              }}
            />
          </div>

          <span className="w-10 font-mono text-sm text-slate-200">
            {Number(alert.threat_score).toFixed(0)}
          </span>
        </div>
      </td>

      <td className="px-4 py-4">
        <span
          className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold tracking-wider ${severity.classes}`}
        >
          {severity.label}
        </span>
      </td>

      <td className="px-4 py-4">
        {alert.anomaly_flag ? (
          <span className="inline-flex items-center gap-2 text-sm font-medium text-red-400">
            <span className="h-2 w-2 animate-pulse rounded-full bg-red-400" />
            ANOMALY
          </span>
        ) : (
          <span className="inline-flex items-center gap-2 text-sm text-emerald-400">
            <span className="h-2 w-2 rounded-full bg-emerald-400" />
            NORMAL
          </span>
        )}
      </td>

      <td className="px-4 py-4">
        <span className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1 font-mono text-xs text-slate-300">
          {alert.suggested_action}
        </span>
      </td>
    </tr>
  );
});

const LiveAnomalyTable = ({ alerts = [] }) => {
  const displayedAlerts = useMemo(
    () => alerts.slice(0, 100),
    [alerts]
  );

  return (
    <section className="overflow-hidden rounded-xl border border-slate-800 bg-slate-950/80 shadow-2xl shadow-black/20">
      <div className="flex items-center justify-between border-b border-slate-800 px-6 py-4">
        <div>
          <h2 className="text-lg font-semibold text-slate-100">
            Live Anomalies
          </h2>

          <p className="mt-1 text-xs uppercase tracking-widest text-slate-500">
            Real-time network threat events
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="h-2 w-2 animate-pulse rounded-full bg-emerald-400" />

          <span className="text-xs font-medium uppercase tracking-wider text-emerald-400">
            Live
          </span>
        </div>
      </div>

      {displayedAlerts.length === 0 ? (
        <div className="flex min-h-48 items-center justify-center text-sm text-slate-500">
          No network anomalies detected.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[1200px] text-left">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/70 text-xs uppercase tracking-wider text-slate-500">
                <th className="px-4 py-3 font-medium">Timestamp</th>
                <th className="px-4 py-3 font-medium">Source</th>
                <th className="px-4 py-3 font-medium">Destination</th>
                <th className="px-4 py-3 font-medium">Protocol</th>
                <th className="px-4 py-3 text-right font-medium">
                  Traffic
                </th>
                <th className="px-4 py-3 font-medium">Threat Score</th>
                <th className="px-4 py-3 font-medium">Severity</th>
                <th className="px-4 py-3 font-medium">Detection</th>
                <th className="px-4 py-3 font-medium">Action</th>
              </tr>
            </thead>

            <tbody>
              {displayedAlerts.map((alert, index) => (
                <LiveAnomalyRow
                  key={[
                    alert.timestamp,
                    alert.src_ip,
                    alert.dst_ip,
                    alert.protocol,
                    alert.byte_count,
                    alert.threat_score,
                    index,
                  ].join("-")}
                  alert={alert}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
};

export default memo(LiveAnomalyTable);