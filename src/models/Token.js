import mongoose from "mongoose";

const tokenSchema = new mongoose.Schema({
  user: { type: mongoose.mongoose.ObjectId, ref: "User", required: true },
  token: { type: String, required: true },
});

export const Token = mongoose.model("Token", tokenSchema);
