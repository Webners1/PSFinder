import { Server as ServerIO } from "socket.io";

//
// import SocketController from '../handlers/socketController';

const connections = [];
const webSocketConnection = (server) => {
  const options = {
    // pingTimeout: 3000,
    // pingInterval: 3000,
    // allowUpgrades: false,
    // upgrade: false,
    // cookie: false,
    cors: {
      origin: "*",
    },
  };
  const io = new ServerIO(server, options);

  io.on("connection", (socket) => {
    console.log("connection made", socket?.id);
    connections.push(socket);
    socket.emit("request" /* … */); // emit an event to the socket
    io.emit("broadcast" /* … */); // emit an event to all connected sockets
    socket.emit("connection established", { socketId: socket.id }); // listen to the event
    // const socketController = new SocketController(socket, io);
    // socketController.registerEvents();
  });
  return io;
};

export { webSocketConnection, connections };
