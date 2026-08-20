import { useEffect, useMemo, useState } from "react";

const API_BASE =
  import.meta.env.VITE_API_BASE_URL ||
  "";

function formatRate(bytesPerSecond) {
  const value = Number(bytesPerSecond) || 0;

  if (value >= 1024 * 1024 * 1024) {
    return `${(value / (1024 * 1024 * 1024)).toFixed(2)} GB/s`;
  }

  if (value >= 1024 * 1024) {
    return `${(value / (1024 * 1024)).toFixed(2)} MB/s`;
  }

  if (value >= 1024) {
    return `${(value / 1024).toFixed(2)} KB/s`;
  }

  return `${value.toFixed(0)} B/s`;
}

function formatTotal(bytes) {
  const value = Number(bytes) || 0;

  if (value >= 1024 * 1024 * 1024) {
    return `${(value / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  }

  if (value >= 1024 * 1024) {
    return `${(value / (1024 * 1024)).toFixed(2)} MB`;
  }

  if (value >= 1024) {
    return `${(value / 1024).toFixed(2)} KB`;
  }

  return `${value.toFixed(0)} B`;
}

function riskFromTelemetry(device) {
  const throughput =
    Number(device.total_bytes_per_second) || 0;

  const destinations =
    Number(device.unique_destinations) || 0;

  const flows =
    Number(device.flows) || 0;

  let score = 0;

  // Throughput contribution
  if (throughput >= 20_000_000) {
    score += 40;
  } else if (throughput >= 5_000_000) {
    score += 32;
  } else if (throughput >= 1_000_000) {
    score += 24;
  } else if (throughput >= 250_000) {
    score += 14;
  } else if (throughput >= 50_000) {
    score += 7;
  }

  // Destination diversity
  if (destinations >= 60) {
    score += 30;
  } else if (destinations >= 30) {
    score += 24;
  } else if (destinations >= 15) {
    score += 16;
  } else if (destinations >= 8) {
    score += 8;
  }

  // Flow pressure
  if (flows >= 60) {
    score += 30;
  } else if (flows >= 35) {
    score += 24;
  } else if (flows >= 20) {
    score += 16;
  } else if (flows >= 10) {
    score += 8;
  }

  return Math.min(100, Math.round(score));
}

function getRiskLabel(score) {
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
}

function getRiskClass(score) {
  if (score >= 90) {
    return "risk-critical";
  }

  if (score >= 75) {
    return "risk-high";
  }

  if (score >= 50) {
    return "risk-medium";
  }

  if (score >= 25) {
    return "risk-low";
  }

  return "risk-normal";
}

export default function DeviceRiskBoard({
  socket,
}) {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function loadDevices() {
    try {
      setError("");

      const response = await fetch(
        `${API_BASE}/api/telemetry/devices`
      );

      if (!response.ok) {
        throw new Error(
          `Telemetry request failed: ${response.status}`
        );
      }

      const result = await response.json();

      const rows = Array.isArray(result?.data)
        ? result.data
        : [];

      setDevices(rows);
    } catch (err) {
      console.error(
        "Failed to load device telemetry:",
        err
      );

      setError(
        "Unable to load device telemetry."
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadDevices();

    // Safety fallback in case socket delivery is temporarily unavailable.
    const interval = setInterval(
      loadDevices,
      5000
    );

    return () => {
      clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    if (!socket) {
      return undefined;
    }

    const handleTelemetry = (device) => {
      setDevices((current) => {
        const key =
          device.device_id ||
          device.src_ip;

        const index = current.findIndex(
          (item) =>
            (
              item.device_id ||
              item.src_ip
            ) === key
        );

        if (index === -1) {
          return [
            device,
            ...current,
          ];
        }

        const next = [
          ...current,
        ];

        next[index] = {
          ...next[index],
          ...device,
        };

        return next;
      });
    };

    socket.on(
      "device_telemetry",
      handleTelemetry
    );

    return () => {
      socket.off(
        "device_telemetry",
        handleTelemetry
      );
    };
  }, [socket]);

  const rankedDevices = useMemo(() => {
    return devices
      .map((device) => {
        const riskScore =
          Number.isFinite(
            Number(device.risk_score)
          )
            ? Number(device.risk_score)
            : riskFromTelemetry(
                device
              );

        return {
          ...device,
          calculated_risk:
            Math.min(
              100,
              Math.max(
                0,
                Math.round(riskScore)
              )
            ),
        };
      })
      .sort(
        (a, b) =>
          b.calculated_risk -
          a.calculated_risk
      );
  }, [devices]);

  if (loading) {
    return (
      <section className="device-risk-board">
        <div className="device-risk-header">
          <div>
            <h2>Device Risk Board</h2>
            <p>
              Live endpoint bandwidth and risk
            </p>
          </div>
        </div>

        <div className="device-risk-empty">
          Loading device telemetry...
        </div>
      </section>
    );
  }

  return (
    <section className="device-risk-board">
      <div className="device-risk-header">
        <div>
          <h2>Device Risk Board</h2>

          <p>
            Live endpoint bandwidth,
            activity and behavioral risk
          </p>
        </div>

        <div className="device-count">
          {rankedDevices.length} device
          {rankedDevices.length === 1
            ? ""
            : "s"}
        </div>
      </div>

      {error && (
        <div className="device-risk-error">
          {error}
        </div>
      )}

      {rankedDevices.length === 0 ? (
        <div className="device-risk-empty">
          No devices have reported telemetry
          yet.
        </div>
      ) : (
        <div className="device-risk-table-wrap">
          <table className="device-risk-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Device</th>
                <th>IP</th>
                <th>Download</th>
                <th>Upload</th>
                <th>Total</th>
                <th>Flows</th>
                <th>Destinations</th>
                <th>Risk</th>
              </tr>
            </thead>

            <tbody>
              {rankedDevices.map(
                (device, index) => {
                  const risk =
                    device.calculated_risk;

                  const riskLabel =
                    getRiskLabel(
                      risk
                    );

                  const riskClass =
                    getRiskClass(
                      risk
                    );

                  return (
                    <tr
                      key={
                        device.device_id ||
                        device.src_ip ||
                        index
                      }
                    >
                      <td>
                        <span className="device-rank">
                          {index + 1}
                        </span>
                      </td>

                      <td>
                        <div className="device-name">
                          {
                            device.hostname ||
                            "Unknown device"
                          }
                        </div>

                        <div className="device-id">
                          {
                            device.device_id ||
                            "No device ID"
                          }
                        </div>
                      </td>

                      <td>
                        {
                          device.src_ip ||
                          "—"
                        }
                      </td>

                      <td>
                        {formatRate(
                          device.bytes_per_second_in
                        )}
                      </td>

                      <td>
                        {formatRate(
                          device.bytes_per_second_out
                        )}
                      </td>

                      <td>
                        {formatRate(
                          device.total_bytes_per_second
                        )}
                      </td>

                      <td>
                        {Number(
                          device.flows
                        ) || 0}
                      </td>

                      <td>
                        {Number(
                          device.unique_destinations
                        ) || 0}
                      </td>

                      <td>
                        <div
                          className={`device-risk-badge ${riskClass}`}
                        >
                          <strong>
                            {risk}
                          </strong>

                          <span>
                            {riskLabel}
                          </span>
                        </div>
                      </td>
                    </tr>
                  );
                }
              )}
            </tbody>
          </table>
        </div>
      )}

      <div className="device-risk-footer">
        <span>
          Live telemetry updates automatically
        </span>

        <span>
          Highest-risk device appears first
        </span>
      </div>
    </section>
  );
}