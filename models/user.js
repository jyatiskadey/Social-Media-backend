const mongoose = require("mongoose");

// DEFINE SCHEMA
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, trim: true, unique: true },
  password: { type: String, required: true, trim: true },
  isActive: { type: Boolean, default: true }, // New field to manage account status
});

const UserModel = mongoose.model("user", userSchema);

module.exports = UserModel;