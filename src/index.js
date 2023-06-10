import "./LoadEnv.js"; // Must be the first import
import app from "./server.js";
import mongoConnection from "./config/db.js";
import { createServer } from "http";
import { webSocketConnection } from "./config/socketConnection.js";

/**
 * Port at which server will run
 */
const port = Number(process.env.PORT || 5000);
const httpServer = createServer(app);
const sio = webSocketConnection(httpServer);

/**
 * Connecting to Database
 */
await mongoConnection();

/**
 * Starting the server
 * @param port Port at which server will run
 */
const server = httpServer.listen(port, () => {
  console.log(`Server Running on Port: http://localhost:${port}`);
});

/**
 * Exporting server instance
 */
export { sio };
export default server;
