import React from "react";
import { useAlerts } from "./hooks/useAlerts";
import LiveAnomalyTable from "./components/LiveAnomalyTable";
import ThreatGraph from "./components/ThreatGraph";

function App() {
  const {
    alerts,
    loading,
    error,
  } = useAlerts();

  const anomalyCount = alerts.filter(
    (alert) => alert.anomaly_flag
  ).length;

  const averageThreatScore =
    alerts.length > 0
      ? alerts.reduce(
          (sum, alert) => sum + Number(alert.threat_score || 0),
          0
        ) / alerts.length
      : 0;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-950/95">
        <div className="mx-auto max-w-[1600px] px-6 py-5">
          <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
            <div>
              <div className="flex items-center gap-3">
                <div className="h-3 w-3 animate-pulse rounded-full bg-cyan-400 shadow-lg shadow-cyan-400/50" />

                <h1 className="text-2xl font-bold tracking-tight text-slate-100">
                  Zero-Trust SOC
                </h1>
              </div>

              <p className="mt-1 text-sm text-slate-500">
                Network Threat Detection & Anomaly Monitoring
              </p>
            </div>

            <div className="flex items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-4 py-2">
              <span className="h-2 w-2 rounded-full bg-emerald-400" />

              <span className="text-xs font-semibold uppercase tracking-widest text-emerald-400">
                System Online
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* Main */}
      <main className="mx-auto max-w-[1600px] space-y-6 px-6 py-6">
        {/* Error */}
        {error && (
          <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-5 py-4 text-sm text-red-400">
            Backend connection error: {error}
          </div>
        )}

        {/* KPI cards */}
        <section className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
            <p className="text-xs font-semibold uppercase tracking-widest text-slate-500">
              Alerts In Memory
            </p>

            <p className="mt-3 text-3xl font-bold text-cyan-400">
              {alerts.length}
            </p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
            <p className="text-xs font-semibold uppercase tracking-widest text-slate-500">
              Anomalies Detected
            </p>

            <p className="mt-3 text-3xl font-bold text-red-400">
              {anomalyCount}
            </p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
            <p className="text-xs font-semibold uppercase tracking-widest text-slate-500">
              Average Threat Score
            </p>

            <p className="mt-3 text-3xl font-bold text-purple-400">
              {averageThreatScore.toFixed(1)}
            </p>
          </div>
        </section>

        {/* Threat graph */}
        <ThreatGraph alerts={alerts} />

        {/* Table */}
        <LiveAnomalyTable alerts={alerts} />

        {/* Loading */}
        {loading && (
          <div className="text-center text-sm text-slate-500">
            Loading alert history...
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
