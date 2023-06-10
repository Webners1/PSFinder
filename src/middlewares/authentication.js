// Libraries
import jwt from "jsonwebtoken";
import { Token } from "../models/Token.js";

export const userAuth = (req, res, next) => {
  try {
    const { authorization } = req.headers;
    const token = authorization.split(" ")[1];
    Token.findOne({ token })
      .exec()
      .then((data) => {
        if (!data) {
          return res.status(404).json({
            status: "rejected",
            message: "Token doesn't exists",
          });
        } else {
          const user = jwt.verify(token, process.env.USER_TOKEN_SECRET);
          req.user = { ...user, oldToken: token };
          next();
        }
      })
      .catch((err) => {
        return res.status(403).json({
          status: "rejected",
          message: "Auth failed",
        });
      });
  } catch (error) {
    return res.status(403).json({
      status: "rejected",
      message: "Auth failed",
    });
  }
};

export const adminAuth = (req, res, next) => {
  try {
    const { authorization } = req.headers;
    const token = authorization.split(" ")[1];
    Token.findOne({ token })
      .exec()
      .then((data) => {
        if (!data) {
          return res.status(404).json({
            status: "rejected",
            message: "Token doesn't exists",
          });
        } else {
          const admin = jwt.verify(token, process.env.ADMIN_TOKEN_SECRET);
          req.admin = { ...admin, oldToken: token };
          next();
        }
      })
      .catch((err) => {
        return res.status(403).json({
          status: "rejected",
          message: "Auth failed",
        });
      });
  } catch (error) {
    return res.status(403).json({
      status: "rejected",
      message: "Auth failed",
    });
  }
};
