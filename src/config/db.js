import mongoose from "mongoose";

const MONGO_URI = process.env.MONGO_URL;

const mongoConnection = async () => {
  try {
    await mongoose.connect(MONGO_URI);
    console.log("mongodb connected successfully");
  } catch (error) {
    console.log("mongodb connection error", error);
  }
};

export default mongoConnection;