import React, {
  memo,
} from "react";

const formatRate = (
  bytesPerSecond
) => {
  if (
    bytesPerSecond <
    1024
  ) {
    return `${bytesPerSecond.toFixed(0)} B/s`;
  }

  if (
    bytesPerSecond <
    1024 * 1024
  ) {
    return `${(
      bytesPerSecond / 1024
    ).toFixed(1)} KB/s`;
  }

  return `${(
    bytesPerSecond /
    (1024 * 1024)
  ).toFixed(2)} MB/s`;
};


const TopConsumers = ({
  devices = [],
}) => {
  const top =
    devices.slice(0, 10);

  return (
    <section className="rounded-xl border border-slate-800 bg-slate-950/80 p-6">
      <div className="mb-5 flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-slate-100">
            Top Network Consumers
          </h2>

          <p className="mt-1 text-xs uppercase tracking-widest text-slate-500">
            Live device bandwidth
          </p>
        </div>

        <span className="rounded-full border border-cyan-500/20 bg-cyan-500/10 px-3 py-1 text-xs text-cyan-400">
          TOP 10
        </span>
      </div>

      {top.length === 0 ? (
        <div className="py-10 text-center text-sm text-slate-500">
          Waiting for device telemetry...
        </div>
      ) : (
        <div className="space-y-3">
          {top.map(
            (
              device,
              index
            ) => {
              const totalRate =
                Number(
                  device.bytes_per_second_in
                ) +
                Number(
                  device.bytes_per_second_out
                );

              return (
                <div
                  key={
                    device.device_id
                  }
                  className="grid grid-cols-[40px_1fr_auto] items-center gap-4 rounded-lg border border-slate-800 bg-slate-900/60 p-3"
                >
                  <div className="font-mono text-sm text-slate-500">
                    #{index + 1}
                  </div>

                  <div>
                    <div className="font-medium text-slate-200">
                      {
                        device.hostname
                      }
                    </div>

                    <div className="mt-1 font-mono text-xs text-cyan-400">
                      {
                        device.src_ip
                      }
                    </div>
                  </div>

                  <div className="text-right">
                    <div className="font-mono text-sm font-semibold text-slate-100">
                      {formatRate(
                        totalRate
                      )}
                    </div>

                    <div className="mt-1 text-xs text-slate-500">
                      {device.flows} flows
                    </div>
                  </div>
                </div>
              );
            }
          )}
        </div>
      )}
    </section>
  );
};

export default memo(
  TopConsumers
);