import React, { useMemo } from "react";

import { useAlerts } from "./hooks/useAlerts";
import LiveAnomalyTable from "./components/LiveAnomalyTable";
import ThreatGraph from "./components/ThreatGraph";
import TopConsumers from "./components/TopConsumers";
import IncidentCenter from "./components/IncidentCenter";
import { useIncidents } from "./hooks/useIncidents";
import {
  useDeviceTelemetry,
} from "./hooks/useDeviceTelemetry";
import DeviceRiskBoard from "./components/DeviceRiskBoard";
import AttackDemoConsole from "./components/AttackDemoConsole";

function App() {
  const {
    incidents = [],
  } = useIncidents();

  const {
    devices = [],
  } = useDeviceTelemetry();

  const {
    alerts = [],
    loading,
    error,
  } = useAlerts();

  // ---------------------------------------------------------------
  // Device count
  // ---------------------------------------------------------------

  const activeDeviceCount = useMemo(() => {
    const uniqueDevices =
      new Set(
        devices.map(
          (device) =>
            device.device_id ||
            device.src_ip
        )
      );

    return uniqueDevices.size;
  }, [devices]);

  // ---------------------------------------------------------------
  // Open incidents
  // ---------------------------------------------------------------

  const openIncidentCount =
    useMemo(() => {
      return incidents.filter(
        (incident) =>
          (
            incident.status ||
            "OPEN"
          ) === "OPEN"
      ).length;
    }, [incidents]);

  // ---------------------------------------------------------------
  // Incident occurrences
  // ---------------------------------------------------------------

  const totalOccurrences =
    useMemo(() => {
      return incidents.reduce(
        (total, incident) =>
          total +
          (
            Number(
              incident.occurrence_count
            ) || 1
          ),
        0
      );
    }, [incidents]);

  // ---------------------------------------------------------------
  // Average incident risk
  // ---------------------------------------------------------------

  const averageRisk =
    useMemo(() => {
      if (
        incidents.length === 0
      ) {
        return 0;
      }

      const total =
        incidents.reduce(
          (sum, incident) =>
            sum +
            (
              Number(
                incident.risk_score
              ) || 0
            ),
          0
        );

      return (
        total /
        incidents.length
      );
    }, [incidents]);

  // ---------------------------------------------------------------
  // Highest-risk device
  // ---------------------------------------------------------------

  const highestRiskDevice =
    useMemo(() => {
      if (
        devices.length === 0
      ) {
        return null;
      }

      return [
        ...devices,
      ].sort(
        (a, b) =>
          (
            Number(
              b.risk_score
            ) || 0
          ) -
          (
            Number(
              a.risk_score
            ) || 0
          )
      )[0];
    }, [devices]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">

      {/* ========================================================= */}
      {/* Header                                                    */}
      {/* ========================================================= */}

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
                Network Threat Detection &
                Anomaly Monitoring
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

      {/* ========================================================= */}
      {/* Main                                                      */}
      {/* ========================================================= */}

      <main className="mx-auto max-w-[1600px] space-y-6 px-6 py-6">

        {/* Backend error */}

        {error && (
          <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-5 py-4 text-sm text-red-400">
            Backend connection error:
            {" "}
            {error}
          </div>
        )}

        {/* ======================================================= */}
        {/* KPI cards                                                */}
        {/* ======================================================= */}

        <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">

          {/* Active devices */}

          <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">

            <p className="text-xs font-semibold uppercase tracking-widest text-slate-500">
              Active Devices
            </p>

            <p className="mt-3 text-3xl font-bold text-cyan-400">
              {activeDeviceCount}
            </p>

            <p className="mt-1 text-xs text-slate-600">
              Unique monitored endpoints
            </p>

          </div>

          {/* Open incidents */}

          <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">

            <p className="text-xs font-semibold uppercase tracking-widest text-slate-500">
              Open Incidents
            </p>

            <p className="mt-3 text-3xl font-bold text-red-400">
              {openIncidentCount}
            </p>

            <p className="mt-1 text-xs text-slate-600">
              Correlated security events
            </p>

          </div>

          {/* Occurrences */}

          <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">

            <p className="text-xs font-semibold uppercase tracking-widest text-slate-500">
              Threat Occurrences
            </p>

            <p className="mt-3 text-3xl font-bold text-orange-400">
              {totalOccurrences}
            </p>

            <p className="mt-1 text-xs text-slate-600">
              Repeated observations
            </p>

          </div>

          {/* Average risk */}

          <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">

            <p className="text-xs font-semibold uppercase tracking-widest text-slate-500">
              Average Risk
            </p>

            <p className="mt-3 text-3xl font-bold text-purple-400">
              {averageRisk.toFixed(1)}
            </p>

            <p className="mt-1 text-xs text-slate-600">
              Across correlated incidents
            </p>

          </div>

        </section>

        {/* ======================================================= */}
        {/* Highest-risk summary                                     */}
        {/* ======================================================= */}

        {highestRiskDevice && (
          <section className="rounded-xl border border-slate-800 bg-slate-900/50 p-4">

            <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">

              <div>
                <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">
                  Highest-risk monitored endpoint
                </p>

                <p className="mt-1 text-sm font-semibold text-slate-100">
                  {
                    highestRiskDevice.hostname ||
                    highestRiskDevice.src_ip ||
                    "Unknown device"
                  }
                </p>
              </div>

              <div className="text-right">

                <p className="text-xs text-slate-500">
                  {highestRiskDevice.src_ip ||
                    "--"}
                </p>

                <p className="text-lg font-bold text-orange-400">
                  Risk{" "}
                  {Number(
                    highestRiskDevice.risk_score ||
                      0
                  ).toFixed(1)}
                </p>

              </div>

            </div>

          </section>
        )}

        {/* ======================================================= */}
        {/* Demo console                                             */}
        {/* ======================================================= */}

        <AttackDemoConsole />

        {/* ======================================================= */}
        {/* Device Risk Board                                        */}
        {/* ======================================================= */}

        <DeviceRiskBoard />

        {/* ======================================================= */}
        {/* Incident Intelligence                                   */}
        {/* ======================================================= */}

        <IncidentCenter
          incidents={
            incidents
          }
        />

        {/* ======================================================= */}
        {/* Top consumers                                           */}
        {/* ======================================================= */}

        <TopConsumers
          devices={
            devices
          }
        />

        {/* ======================================================= */}
        {/* Threat graph                                             */}
        {/* ======================================================= */}

        <ThreatGraph
          alerts={
            alerts
          }
        />

        {/* ======================================================= */}
        {/* Live anomaly table                                      */}
        {/* ======================================================= */}

        <LiveAnomalyTable
          alerts={
            alerts
          }
        />

        {/* ======================================================= */}
        {/* Loading                                                  */}
        {/* ======================================================= */}

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