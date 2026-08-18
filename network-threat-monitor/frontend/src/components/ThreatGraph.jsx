import React, { memo, useMemo } from "react";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ReferenceLine,
} from "recharts";

const ThreatGraph = ({ alerts = [] }) => {
  const chartData = useMemo(() => {
    return [...alerts]
      .reverse()
      .map((alert) => ({
        timestamp: alert.timestamp,
        time: new Date(alert.timestamp).toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }),
        threat_score: Number(alert.threat_score),
        anomaly_flag: alert.anomaly_flag,
      }));
  }, [alerts]);

  return (
    <section className="rounded-xl border border-slate-800 bg-slate-950/80 p-6 shadow-2xl shadow-black/20">
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h2 className="text-lg font-semibold text-slate-100">
            Threat Score Timeline
          </h2>

          <p className="mt-1 text-xs uppercase tracking-widest text-slate-500">
            Isolation Forest anomaly confidence
          </p>
        </div>

        <div className="flex items-center gap-2 rounded-full border border-cyan-500/20 bg-cyan-500/5 px-3 py-1.5">
          <span className="h-2 w-2 rounded-full bg-cyan-400" />

          <span className="text-xs font-medium uppercase tracking-wider text-cyan-400">
            0–100
          </span>
        </div>
      </div>

      <div className="h-[350px] w-full">
        {chartData.length === 0 ? (
          <div className="flex h-full items-center justify-center text-sm text-slate-500">
            Waiting for anomaly telemetry...
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart
              data={chartData}
              margin={{
                top: 10,
                right: 20,
                left: 0,
                bottom: 10,
              }}
            >
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="rgba(148,163,184,0.08)"
              />

              <XAxis
                dataKey="time"
                tick={{
                  fill: "#64748b",
                  fontSize: 11,
                }}
                axisLine={{
                  stroke: "#1e293b",
                }}
                tickLine={false}
              />

              <YAxis
                domain={[0, 100]}
                tick={{
                  fill: "#64748b",
                  fontSize: 11,
                }}
                axisLine={{
                  stroke: "#1e293b",
                }}
                tickLine={false}
              />

              <Tooltip
                contentStyle={{
                  backgroundColor: "#020617",
                  border: "1px solid #1e293b",
                  borderRadius: "8px",
                  color: "#e2e8f0",
                }}
                labelStyle={{
                  color: "#94a3b8",
                  marginBottom: "4px",
                }}
                formatter={(value) => [
                  Number(value).toFixed(1),
                  "Threat Score",
                ]}
              />

              <ReferenceLine
                y={80}
                stroke="#ef4444"
                strokeDasharray="5 5"
                label={{
                  value: "HIGH",
                  fill: "#f87171",
                  fontSize: 10,
                }}
              />

              <ReferenceLine
                y={60}
                stroke="#f59e0b"
                strokeDasharray="5 5"
                label={{
                  value: "MEDIUM",
                  fill: "#fbbf24",
                  fontSize: 10,
                }}
              />

              <Line
                type="monotone"
                dataKey="threat_score"
                stroke="#22d3ee"
                strokeWidth={2}
                dot={{
                  r: 3,
                  fill: "#22d3ee",
                }}
                activeDot={{
                  r: 6,
                  fill: "#67e8f9",
                }}
                isAnimationActive
                animationDuration={400}
              />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </section>
  );
};

export default memo(ThreatGraph);