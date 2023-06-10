import express from "express";
import cors from "cors";
import helmet from "helmet";
import sgMail from "@sendgrid/mail";

// Route imports
import UserRouter from "./routes/user.routes.js";

/**
 * Init express
 */
const app = express();

/**
 * Cors setup
 */
var whitelist = [
  "http://localhost:3000",
  "http://localhost:3001",
  "http://localhost:3002",
];
var corsOptions = {
  origin: function (origin, callback) {
    if (whitelist.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
};
app.use(cors());

/**
 * Set basic express settings
 */
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true }));

/**
 * Helmet for basic security in production
 */
if (process.env.NODE_ENV === "production") {
  app.use(
    helmet({
      crossOriginResourcePolicy: false,
    })
  );
}

/**
 * Sendgrid setup
 */
sgMail.setApiKey(process.env.SENDGRID_API_KEY);
app.set("sgMail", sgMail);

/**
 * Registering base API routes
 */
app.use("/api/v1/user", UserRouter);

/**
 * Entry route
 */
app.use("/", (req, res) =>
  res.status(200).send("Welcome to Crypto Gateway Server")
);

/**
 * Catch API errors throughout the application
 */
app.use((req, res, next) => {
  const err = new Error("Not Found");
  err.status = 404;
  next(err);
});

app.use((err, req, res, next) => {
  console.log(err);
  if (err.status === 404) res.status(404).json({ message: "Not found" });
  else res.status(500).json({ message: "Something looks wrong :( !!!" });
});

/**
 * Exporting express app instance
 */
export default app;
