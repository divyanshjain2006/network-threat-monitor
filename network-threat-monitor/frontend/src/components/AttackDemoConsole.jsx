import React, {
  memo,
  useState,
} from "react";

const scenarios = [
  {
    id: "normal_web",
    label: "Normal Web",
    description:
      "Generate baseline HTTPS traffic.",
  },

  {
    id: "normal_dns",
    label: "Normal DNS",
    description:
      "Generate ordinary DNS activity.",
  },

  {
    id: "traffic_burst",
    label: "Traffic Burst",
    description:
      "Generate a sudden high-volume burst.",
  },

  {
    id: "destination_sweep",
    label: "Port / Host Sweep",
    description:
      "Generate synthetic scanning behavior.",
  },

  {
    id: "connection_flood",
    label: "Connection Flood",
    description:
      "Generate many synthetic short-lived flows.",
  },
  {
    id: "data_exfiltration",
    label: "Data Exfiltration",
    description:
        "Generate synthetic sustained outbound transfer behavior.",
    },
];

const AttackDemoConsole = () => {
  const [loading, setLoading] =
    useState(null);

  const [result, setResult] =
    useState(null);

  const triggerScenario = async (
    scenario
  ) => {
    try {
      setLoading(scenario.id);
      setResult(null);

      const response = await fetch(
        "/api/simulator/scenario",
        {
          method: "POST",

          headers: {
            "Content-Type":
              "application/json",
          },

          body: JSON.stringify({
            scenario: scenario.id,
          }),
        }
      );

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data.message ||
            "Failed to trigger scenario."
        );
      }

      setResult({
        success: true,
        message:
          data.message ||
          "Scenario triggered.",
      });
    } catch (error) {
      setResult({
        success: false,
        message: error.message,
      });
    } finally {
      setLoading(null);
    }
  };

  return (
    <section className="rounded-xl border border-slate-800 bg-slate-950/80 p-6">
      <div className="mb-5">
        <div className="flex items-center gap-3">
          <div className="h-2.5 w-2.5 rounded-full bg-purple-400" />

          <h2 className="text-lg font-semibold text-slate-100">
            Attack Simulation Console
          </h2>
        </div>

        <p className="mt-1 text-xs uppercase tracking-widest text-slate-500">
          Safe synthetic scenarios for live demonstrations
        </p>
      </div>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
        {scenarios.map(
          (scenario) => (
            <button
              key={scenario.id}
              type="button"
              disabled={
                loading !== null
              }
              onClick={() =>
                triggerScenario(
                  scenario
                )
              }
              className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 text-left transition hover:border-purple-500/40 hover:bg-purple-500/5 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="font-semibold text-slate-200">
                    {scenario.label}
                  </p>

                  <p className="mt-1 text-xs leading-5 text-slate-500">
                    {scenario.description}
                  </p>
                </div>

                {loading ===
                  scenario.id && (
                  <span className="text-xs text-purple-400">
                    ...
                  </span>
                )}
              </div>
            </button>
          )
        )}
      </div>

      {result && (
        <div
          className={`mt-4 rounded-lg border p-3 text-sm ${
            result.success
              ? "border-emerald-500/20 bg-emerald-500/5 text-emerald-400"
              : "border-red-500/20 bg-red-500/5 text-red-400"
          }`}
        >
          {result.message}
        </div>
      )}
    </section>
  );
};

export default memo(
  AttackDemoConsole
);