import { io } from "socket.io-client";

const SOCKET_URL =
  import.meta.env.VITE_BACKEND_URL || "http://localhost:5000";

let socket = null;

/**
 * Initialize and return the singleton Socket.io connection.
 *
 * Calling this function multiple times returns the same socket instance.
 */
export const getAlertSocket = () => {
  if (!socket) {
    socket = io(SOCKET_URL, {
      transports: ["websocket"],
      autoConnect: true,
      reconnection: true,
      reconnectionAttempts: Infinity,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
    });
  }

  return socket;
};

/**
 * Disconnect the singleton socket.
 */
export const disconnectAlertSocket = () => {
  if (socket) {
    socket.disconnect();
    socket = null;
  }
};

export default getAlertSocket;