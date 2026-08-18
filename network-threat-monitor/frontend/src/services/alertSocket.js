import { io } from "socket.io-client";

let socket = null;

export const getAlertSocket = () => {
  if (!socket) {
    /*
     * Connect to the current frontend origin.
     *
     * Vite proxies /socket.io -> http://127.0.0.1:5000
     */
    socket = io(window.location.origin, {
      transports: ["websocket"],
      path: "/socket.io",
      reconnection: true,
      reconnectionAttempts: Infinity,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
    });
  }

  return socket;
};

export const disconnectAlertSocket = () => {
  if (socket) {
    socket.disconnect();
    socket = null;
  }
};

export default getAlertSocket;