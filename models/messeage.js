const mongoose = require("mongoose");

const messageSchema = new mongoose.Schema(
  {
    recipient: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "user",
      required: true,
    },
    name: { type: mongoose.Schema.Types.ObjectId, ref: "user" },

    message: { type: String, required: true },
  },
  { timestamps: true }
);

const MessageModel = mongoose.model("Message", messageSchema);

module.exports = MessageModel;
