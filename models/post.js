const mongoose = require("mongoose");

const postSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
    },
    description: {
      type: String,
      required: true,
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "user", // Reference to the User model
      required: true,
    },
    userName: {
      type: String,
      required: true,
    },
    imageUrl: {
      type: String,
      default: null, // Optional image URL
    },
    comments: [
      {
        userId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "user", // Reference to the User model
          required: true,
        },
        userName: {
          type: String,
          required: true,
        },
        text: {
          type: String,
          required: true,
        },
        createdAt: {
          type: Date,
          default: Date.now,
        },
      },
    ],
  },
  {
    timestamps: true, // Automatically adds createdAt and updatedAt timestamps
  }
);

// Optional: Index on userId for performance
postSchema.index({ userId: 1 });
postSchema.index({ "comments.userId": 1 });

const PostModel = mongoose.model("post", postSchema);

module.exports = PostModel;