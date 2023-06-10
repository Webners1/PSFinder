import express from "express";
import { validateBody } from "../middlewares/validateBody.js";
import {
  emailReqSchema,
  resetPassSchema,
  signInUserSchema,
  signUpUserSchema,
  tokenReqSchema,
} from "../schemaValidation/user.schema.js";
import {
  signIn,
  signInWithAuth,
  signUp,
  signOut,
  verifyAccount,
  forgetPass,
  resetPass,
} from "../controllers/user.controllers.js";
import { userAuth } from "../middlewares/authentication.js";

const router = express.Router();

router.post("/sign-up", validateBody(signUpUserSchema), signUp);
router.put("/verify-account", validateBody(tokenReqSchema), verifyAccount);
router.post("/sign-in", validateBody(signInUserSchema), signIn);
router.put("/sign-in-with-auth", userAuth, signInWithAuth);
router.delete("/sign-out", validateBody(tokenReqSchema), signOut);
router.post("/forget-pass", validateBody(emailReqSchema), forgetPass);
router.put("/reset-pass", validateBody(resetPassSchema), resetPass);

export default router;
