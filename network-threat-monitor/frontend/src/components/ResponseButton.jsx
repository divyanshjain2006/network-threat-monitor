import React, {
  useState,
} from "react";

const ResponseButton = ({
  incident,
}) => {
  const [
    executing,
    setExecuting,
  ] = useState(false);

  const [
    result,
    setResult,
  ] = useState(null);

  const executeResponse = async () => {
    try {
      setExecuting(true);
      setResult(null);

      const response = await fetch(
        "/api/responses/execute",
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/json",
          },
          body: JSON.stringify({
            incident_id:
              incident.incident_id,

            device_id:
              incident.device_id,

            action:
              incident.suggested_action,
          }),
        }
      );

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data.message ||
            "Response failed."
        );
      }

      setResult(data.data);
    } catch (error) {
      setResult({
        status: "FAILED",
        error: error.message,
      });
    } finally {
      setExecuting(false);
    }
  };

  return (
    <div className="mt-5">
      <button
        onClick={executeResponse}
        disabled={executing}
        className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-2 text-sm font-semibold text-red-400 transition hover:bg-red-500/20 disabled:cursor-not-allowed disabled:opacity-50"
      >
        {executing
          ? "Executing..."
          : `Execute ${incident.suggested_action}`}
      </button>

      {result && (
        <div className="mt-3 rounded-lg border border-slate-800 bg-slate-950 p-3 text-sm">
          <p className="font-semibold text-slate-200">
            Response: {result.status}
          </p>

          {result.mode && (
            <p className="mt-1 text-xs text-slate-500">
              Mode: {result.mode}
            </p>
          )}
        </div>
      )}
    </div>
  );
};

export default ResponseButton;