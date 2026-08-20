import {
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  getAlertSocket,
} from "../services/alertSocket";


export const useDeviceTelemetry = () => {
  const [devices, setDevices] =
    useState([]);

  useEffect(() => {
    let cancelled = false;

    const loadDevices = async () => {
      try {
        const response =
          await fetch(
            "/api/telemetry/devices"
          );

        if (!response.ok) {
          return;
        }

        const result =
          await response.json();

        if (
          !cancelled &&
          Array.isArray(result.data)
        ) {
          setDevices(
            result.data
          );
        }
      } catch (error) {
        console.error(
          "Failed to load device telemetry:",
          error
        );
      }
    };

    loadDevices();

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const socket =
      getAlertSocket();

    const handleTelemetry =
      (record) => {
        setDevices(
          (current) => {
            const filtered =
              current.filter(
                (device) =>
                  device.device_id !==
                  record.device_id
              );

            return [
              record,
              ...filtered,
            ];
          }
        );
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
  }, []);

  const rankedDevices =
    useMemo(
      () =>
        [...devices].sort(
          (
            a,
            b
          ) =>
            (
              b.bytes_per_second_in +
              b.bytes_per_second_out
            ) -
            (
              a.bytes_per_second_in +
              a.bytes_per_second_out
            )
        ),
      [devices]
    );

  return {
    devices: rankedDevices,
  };
};