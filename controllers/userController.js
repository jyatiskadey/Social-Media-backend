const express = require("express");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const UserModel = require("../models/user");
const PostModel = require("../models/post");
const Admin = require("../models/admin")
const Notification = require('../models/notification')
const MessageModel = require("../models/messeage.js")


const { default: mongoose } = require("mongoose");
// Adjust the path according to your file structure

require("dotenv").config();

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Configure Multer for local file storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/"); // Temporary folder for uploads
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // Unique filenames
  },
});

const upload = multer({ storage });

const userController = {
  //User Registration
  userRegistration: async (req, res) => {
    try {
      const { name, email, password, passwordConfirmation } = req.body;

      const user = await UserModel.findOne({ email });
      if (user) {
        return res
          .status(400)
          .send({ status: "failed", message: "Email already exists" });
      }

      if (!name || !email || !password || !passwordConfirmation) {
        return res
          .status(400)
          .send({ status: "failed", message: "All fields are required" });
      }

      if (password !== passwordConfirmation) {
        return res
          .status(400)
          .send({ status: "failed", message: "Passwords do not match" });
      }

      const salt = await bcrypt.genSalt(12);
      const hashPassword = await bcrypt.hash(password, salt);

      const newUser = new UserModel({
        name,
        email,
        password: hashPassword,
      });

      await newUser.save();
      const saved_user = await UserModel.findOne({ email }); // Use an object as the filter

      const token = jwt.sign(
        { userID: saved_user._id },
        process.env.JWT_PRIVATE_KEY,
        { expiresIn: "15d" }
      );
      res.status(201).send({
        status: "success",
        token: token,
      });
    } catch (error) {
      console.error("Error during registration:", error);
      res
        .status(500)
        .send({ status: "failed", message: "Internal server error" });
    }
  },

  // User Login
  userLogin :async (req, res) => {
    const { email, password } = req.body;
  
    try {
      // Find user by email
      const user = await UserModel.findOne({ email });
  
      if (!user) {
        return res.status(404).json({ message: "User not found." });
      }
  
      // Check if the user's account is active
      if (!user.isActive) {
        return res.status(403).json({ message: "Account is deactivated. Please contact admin." });
      }
  
      // Compare the provided password with the hashed password in the database
      const isPasswordMatch = await bcrypt.compare(password, user.password);
      if (!isPasswordMatch) {
        return res.status(401).json({ message: "Invalid email or password." });
      }
  
      // Generate a JWT token
      const token = jwt.sign({ id: user._id }, process.env.JWT_PRIVATE_KEY, { expiresIn: "1h" });
  
      // Return the response
      return res.status(200).json({
        message: "Login successful.",
        token,
        user: { id: user._id, name: user.name, email: user.email },
        
      });
    } catch (error) {
      console.error("Error during login:", error);
      return res.status(500).json({ message: "Internal server error." });
    }
  },
  

  //citizen user deatils
  citizenUserDetails: async (req, res) => {
    try {
      const token = req.headers.authorization?.split(" ")[1]; // Extract token from the Authorization header
  
      if (!token) {
        return res.status(401).send({ status: "failed", message: "Token is missing" });
      }
  
      // Verify the token
      const decoded = jwt.verify(token, process.env.JWT_PRIVATE_KEY);
  
      if (!decoded || !decoded.id) {
        return res.status(401).send({ status: "failed", message: "Invalid token" });
      }
  
      // Find user by ID
      const user = await UserModel.findById(decoded.id).select("_id name email");
  
      if (!user) {
        return res.status(404).send({ status: "failed", message: "User not found" });
      }
  
      // Return user details
      res.status(200).send({
        status: "success",
        message: "User details fetched successfully",
        user,
      });
    } catch (error) {
      console.error("Error fetching user details:", error);
      res.status(500).send({ status: "failed", message: "Internal server error" });
    }
  },
  

  //  USER PASSWORD CHAHNGE
  changePassword: async (req, res) => {
    const { password, passwordConfirmation } = req.body;
    if (password && passwordConfirmation) {
      if (password !== passwordConfirmation) {
        res.status(500).send({
          status: "failed",
          message: "Password and confirm password does not match",
        });
      } else {
        const salt = await bcrypt.genSalt(12);
        const newhashPassword = await bcrypt.hash(password, salt);
        await UserModel.findByIdAndUpdate(req.user._id, {
          $set: { password: newhashPassword },
        });
        res
          .status(200)
          .send({ status: "sucess", message: "Password Reset sucessfully" });
      }
    } else {
      res
        .status(500)
        .send({ status: "failed", message: "All fileds are required" });
    }
  },

  //  GET  POST ROUTE
  getUserPosts: async (req, res) => {
    try {
      if (!req.user || !req.user._id) {
        return res
          .status(400)
          .json({ success: false, message: "User not authenticated." });
      }

      const userId = req.user._id; // Get the userId from the authenticated user

      // Find posts created by the authenticated user
      const posts = await PostModel.find({ userId }).populate("userId"); // Ensure userId is populated in posts

      if (!posts || posts.length === 0) {
        return res
          .status(404)
          .json({ success: false, message: "No posts found for this user." });
      }

      res.status(200).json({ success: true, posts });
    } catch (error) {
      console.error("Error fetching posts:", error);
      res.status(500).json({ success: false, message: "Error fetching posts" });
    }
  },

  //  DELETE  POST ROUTE
  deletePost: async (req, res) => {
    const { postId } = req.params;
  
    try {
      // Find the post by its ID
      const post = await PostModel.findById(postId);
  
      if (!post) {
        return res.status(404).json({ message: "Post not found" });
      }
  
      // Access the current user's ID from req.user (set by checkUserAuth middleware)
      const currentUserId = req.user._id; // Use req.user._id, not req.userId
      if (!currentUserId) {
        return res.status(401).json({ message: "Unauthorized: No user ID provided" });
      }
  
      // Check if the logged-in user is the author of the post
      if (!post.userId || post.userId.toString() !== currentUserId.toString()) {
        return res.status(403).json({ message: "You are not authorized to delete this post" });
      }
  
      // Delete the post
      await PostModel.findByIdAndDelete(postId);
  
      // Return success response
      res.status(200).json({ message: "Post deleted successfully" });
    } catch (error) {
      console.error("Error deleting post:", error);  // Log any server errors
      res.status(500).json({ message: "Server error, unable to delete post" });
    }
  },
  
  
  

  // Edit Post Route
  editPost: async (req, res) => {
    const { postId } = req.params; // Get the post ID from the request parameters
    const { title, description } = req.body; // Get the new data from the request body
    const token = req.headers.authorization?.split(" ")[1]; // Get token from Authorization header
  
    if (!token) {
      return res.status(401).json({ message: "Unauthorized, no token provided" });
    }
  
    try {
      // Verify the token and decode it
      const decoded = jwt.verify(token, process.env.JWT_PRIVATE_KEY); // Ensure your secret is set correctly
      if (!decoded || !decoded.id) { // Ensure the decoded token has the correct field name for user ID
        return res.status(401).json({ message: "Invalid token" });
      }
  
      // Find the post by ID
      const post = await PostModel.findById(postId);
  
      if (!post) {
        return res.status(404).json({ message: "Post not found" });
      }
  
      // Check if the logged-in user is the author of the post
      if (post.userId.toString() !== decoded.id.toString()) {
        return res.status(403).json({ message: "You are not authorized to edit this post" });
      }
  
      // Update post data with the fields provided in the request body
      post.title = title || post.title; // Only update title if provided
      post.description = description || post.description; // Only update description if provided
  
      // Save the updated post
      await post.save();
  
      // Return success response with the updated post
      res.status(200).json({ message: "Post updated successfully", post });
    } catch (error) {
      console.error("Error updating post:", error);
      res.status(500).json({ message: "Server error, unable to update post" });
    }
  },  
  

   registerAdmin:async (req, res) => {
    const { email, password } = req.body;
  
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }
  
    try {
      // Check if admin already exists
      const existingAdmin = await Admin.findOne({ email });
      if (existingAdmin) {
        return res.status(400).json({ message: 'Admin already exists with this email.' });
      }
  
      // Create a new admin
      const newAdmin = new Admin({ email, password });
      await newAdmin.save();
  
      res.status(201).json({ message: 'Admin registered successfully.' });
    } catch (error) {
      console.error('Error registering admin:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  },

   adminLogin:async (req, res) => {
    const { email, password } = req.body;
  
    if (!email || !password) {
      return res.status(400).json();
    }
  
    try {
      const admin = await Admin.findOne({ email });
      if (!admin) {
        return res.status(404).json();
      }
  
      // Compare password with hashed password in the database
      const isPasswordValid = await bcrypt.compare(password, admin.password);
      if (!isPasswordValid) {
        return res.status(400).json();
      }
  
      // Generate JWT token
      const token = jwt.sign({ adminId: admin._id }, process.env.JWT_PRIVATE_KEY, { expiresIn: '15' });
  
      res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
      console.error('Error during admin login:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  },

  // Toggle User Account Status
  adminUserToggle: async (req, res) => {
    const { userId } = req.params;
  
    try {
      // Find user by ID
      const user = await UserModel.findById(userId);
  
      if (!user) {
        return res.status(404).json({ message: "User not found." });
      }
  
      // Toggle the user's `isActive` status
      user.isActive = !user.isActive;
  
      // Save changes to the database
      await user.save();
  
      return res.status(200).json({
        message: `User ${user.isActive ? "activated" : "deactivated"} successfully.`,
        isActive: user.isActive,
      });
    } catch (error) {
      console.error("Error toggling user status:", error);
      return res.status(500).json({ message: "Internal server error." });
    }
  },
  

  getAllUsers: async (req, res) => {
    try {
      const page = parseInt(req.query.page) || 1;  // Default to page 1 if not provided
      const limit = parseInt(req.query.limit) || 5; // Default to 5 users per page if not provided
      const skip = (page - 1) * limit;  // Skip the number of users based on the current page
      
      // Get the search term if provided
      const searchTerm = req.query.searchTerm || '';
  
      // Build the search query
      const searchQuery = searchTerm
        ? {
            $or: [
              { name: { $regex: searchTerm, $options: 'i' } },  // Search by name (case-insensitive)
              { email: { $regex: searchTerm, $options: 'i' } }, // Search by email (case-insensitive)
            ],
          }
        : {}; // If no search term, fetch all users
  
      // Fetch users with pagination and search
      const users = await UserModel.find(searchQuery, "name email isActive")
        .skip(skip)  // Skip the first 'skip' users
        .limit(limit);  // Limit to the number of 'limit' users per page
  
      // Count the total number of users to calculate total pages (based on search filter)
      const totalUsers = await UserModel.countDocuments(searchQuery);
  
      // Calculate total pages
      const totalPages = Math.ceil(totalUsers / limit);
  
      // Return the users, total user count, and total pages
      return res.status(200).json({
        users,
        totalUsers,
        totalPages,
        currentPage: page,
      });
    } catch (error) {
      console.error("Error fetching users:", error);
      return res.status(500).json({ message: "Internal server error." });
    }
  },
  
  getAllPosts: async (req, res) => {
    try {
      // Get page, limit, searchTerm, sortField, and sortOrder from query parameters
      const page = parseInt(req.query.page) || 1; // Default to page 1
      const limit = parseInt(req.query.limit) || 5; // Default to 5 posts per page
      const searchTerm = req.query.searchTerm || ""; // Search term for filtering
      const sortField = req.query.sortField || "createdAt"; // Default to sorting by createdAt
      const sortOrder = req.query.sortOrder === "desc" ? -1 : 1; // Default to ascending order
  
      // Calculate the number of posts to skip (for pagination)
      const skip = (page - 1) * limit;
  
      // Build a dynamic query for searching
      const query = searchTerm
        ? {
            $or: [
              { title: { $regex: searchTerm, $options: "i" } }, // Match title (case-insensitive)
              { description: { $regex: searchTerm, $options: "i" } }, // Match description (case-insensitive)
              { userName: { $regex: searchTerm, $options: "i" } } // Match userName (case-insensitive)
            ]
          }
        : {};
  
      // Fetch posts based on query, limit, skip, and sort
      const posts = await PostModel.find(query)
        .select("title description userId userName imageUrl createdAt updatedAt")
        .skip(skip) // Skip the posts for the current page
        .limit(limit) // Limit the number of posts per page
        .sort({ [sortField]: sortOrder }); // Sort the posts based on sortField and sortOrder
  
      // Get the total number of posts matching the query
      const totalPosts = await PostModel.countDocuments(query);
  
      // Calculate the total number of pages
      const totalPages = Math.ceil(totalPosts / limit);
  
      return res.status(200).json({
        posts,
        totalPosts,
        totalPages,
        currentPage: page,
      });
    } catch (error) {
      console.error("Error fetching posts:", error);
      return res.status(500).json({ message: "Internal server error." });
    }
  },

  seeAllPosts: async (req, res) => {
    try {
      // Helper function to limit the text to 15 words
      const limitWords = (text, wordLimit = 15) => {
        const words = text.split(" ");
        return words.slice(0, wordLimit).join(" ") + (words.length > wordLimit ? "..." : "");
      };
  
      // Fetch all posts from the database
      const posts = await PostModel.find({}, "userName title description imageUrl")
        .sort({ createdAt: -1 }); // Optional: Sort posts by the latest first
  
      // Check if posts exist
      if (!posts || posts.length === 0) {
        return res.status(404).json({
          status: "failed",
          message: "No posts found",
        });
      }
  
      // Trim the title and description to 15 words
      const postsWithLimitedText = posts.map(post => ({
        ...post.toObject(),
        title: limitWords(post.title),
        description: limitWords(post.description),
      }));
  
      // Return the posts with limited title and description
      res.status(200).json({
        status: "success",
        message: "Posts fetched successfully",
        posts: postsWithLimitedText,
      });
    } catch (error) {
      console.error("Error fetching posts:", error);
      res.status(500).json({
        status: "failed",
        message: "Internal server error",
      });
    }
  },
  


// Route to fetch a single post by ID
getPostByID: async (req, res) => {
  try {
    const { id } = req.params;
    console.log("Request ID:", id); // Log ID from params

    const post = await PostModel.findById(id).select(
      "title description userId userName imageUrl createdAt updatedAt"
    );

    if (!post) {
      console.log("Post not found for ID:", id);
      return res.status(404).json({ message: "Post not found." });
    }

    console.log("Fetched Post:", post);
    return res.status(200).json(post);
  } catch (error) {
    console.error("Error fetching post:", error);
    return res.status(500).json({ message: "Internal server error." });
  }
},

  createNotification: async (req, res) => {
  try {
    const { title, message } = req.body;

    // Validate input
    if (!title || !message) {
      return res.status(400).json({ error: "Title and message are required." });
    }

    // Create and save the notification
    const newNotification = new Notification({ title, message });
    const savedNotification = await newNotification.save();

    return res.status(201).json({
      message: "Notification created successfully.",
      notification: savedNotification,
    });
  } catch (error) {
    console.error("Error creating notification:", error);
    return res.status(500).json({ error: "Internal server error." });
  }
},

getAllNotifications: async (req, res) => {
  try {
    // Fetch all notifications from the database, sorted by most recent first
    const notifications = await Notification.find().sort({ createdAt: -1 });

    // Add a serial number to each notification
    const notificationsWithNumbers = notifications.map((notification, index) => ({
      number: index + 1, // Serial number starts from 1
      ...notification._doc, // Spread the existing notification data
    }));

    return res.status(200).json({
      message: "Notifications fetched successfully.",
      notifications: notificationsWithNumbers,
    });
  } catch (error) {
    console.error("Error fetching notifications:", error);
    return res.status(500).json({ error: "Internal server error." });
  }
},

 deleteNotification : async (req, res) => {
  const { id } = req.params;

  try {
    // Find and delete the notification
    const notification = await Notification.findByIdAndDelete(id);

    if (!notification) {
      return res.status(404).json({ message: "Notification not found" });
    }

    res.status(200).json({ message: "Notification deleted successfully" });
  } catch (error) {
    console.error("Error deleting notification:", error);
    res.status(500).json({ message: "Internal server error" });
  }
},

 fetchActiveUsers : async (req, res) => {
  try {
    const users = await UserModel.find({ isActive: true }).select("name");
    res.status(200).json(users); // Send back an array of user names
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ message: "Error fetching users" });
  }
},

// Route to send a message
 sendMessageRoute : async (req, res) => {
  const {recipientId, message } = req.body;
  

  try {
    // Check if senderId, recipientId, and message are provided
    if ( !recipientId || !message) {
      return res.status(400).json({ message: "Sender, recipient, and message are required" });
    }

    // Save the message in the database
    const newMessage = new MessageModel({
      recipient: recipientId, 
      message,
    });
    await newMessage.save();

    res.status(201).json({ message: "Message sent successfully" });
  } catch (error) {
    console.error("Error sending message:", error);
    res.status(500).json({ message: "Failed to send the message" });
  }
},

 getUserMessagesRoute : async (req, res) => {
  const userId = req.user._id; // Access the authenticated user's ID from req.user

  try {
    // Find all messages for the logged-in user where the user is the recipient
    const messages = await MessageModel.find({ recipient: userId })
      .populate('recipient', 'name email') // Populating recipient's information
      .sort({ createdAt: -1 }); // Sorting by most recent

    if (!messages || messages.length === 0) {
      return res.status(404).json({  });
    }

    res.status(200).json({ messages });
  } catch (error) {
    console.error("Error fetching messages:", error);
    res.status(500).json({ message: "Failed to fetch messages" });
  }
},

getAllMessagesRoute: async (req, res) => {
  const { userId } = req.params;

  try {
    // Fetch messages where the recipient is the userId passed in the request
    const messages = await MessageModel.find({ recipient: userId })
      .populate("recipient", "name email") // Populate the recipient details (name, email)
      .populate("name", "name email") // Populate the sender details (name, email)
      .sort({ createdAt: -1 }); // Sort by most recent first

    // Check if messages are found
    if (!messages || messages.length === 0) {
      return res.status(404).json({ message: "No messages found" });
    }

    // Return the found messages
    res.status(200).json({ messages });
  } catch (error) {
    console.error("Error fetching messages:", error);
    res.status(500).json({ message: "Failed to retrieve messages" });
  }
},

 addComment : async (req, res) => {
  const { postId } = req.params;
  const { comment } = req.body;

  if (!comment || comment.trim() === "") {
    return res.status(400).json({ success: false, message: "Comment cannot be empty!" });
  }

  try {
    // Find the post by ID
    const post = await PostModel.findById(postId);
    if (!post) {
      return res.status(404).json({ success: false, message: "Post not found!" });
    }

    // Add the comment to the post
    const newComment = {
      userId: req.user.id, // Retrieved from verifyToken middleware
      userName: req.user.name, // Retrieved from verifyToken middleware
      text: comment,
    };

    post.comments.push(newComment);
    await post.save();

    return res.status(201).json({ success: true, message: "Comment added successfully!", post });
  } catch (error) {
    console.error("Error adding comment:", error);
    return res.status(500).json({ success: false, message: "Internal server error." });
  }
},

// Route to get comments for a post filtered by the logged-in user's ID
getComments: async (req, res) => {
  const { postId } = req.params;

  try {
    // Find the post by ID
    const post = await PostModel.findById(postId);
    if (!post) {
      return res.status(404).json({ success: false, message: "Post not found!" });
    }

    const userComments = post.comments.filter(comment => comment.userId.toString() === req.user.id.toString());

    if (userComments.length === 0) {
      return res.status(404).json({ success: false, message: "No comments found for this user." });
    }

    // Return the filtered comments
    return res.status(200).json({ success: true, comments: userComments });
  } catch (error) {
    console.error("Error fetching comments:", error);
    return res.status(500).json({ success: false, message: "Internal server error." });
  }
},

getAllComments: async (req, res) => {
  const { postId } = req.params;

  try {
    // Find the post by ID
    const post = await PostModel.findById(postId).select("comments");

    if (!post) {
      return res.status(404).json({ success: false, message: "Post not found!" });
    }

    // If the post has no comments
    if (post.comments.length === 0) {
      return res.status(200).json({ success: true, message: "No comments found for this post.", comments: [] });
    }

    // Return all comments
    return res.status(200).json({
      success: true,
      message: "Comments fetched successfully!",
      comments: post.comments,
    });
  } catch (error) {
    console.error("Error fetching comments:", error);
    return res.status(500).json({ success: false, message: "Internal server error." });
  }
},


//   if (!text || text.trim() === "") {
//     throw new Error("Comment text cannot be empty.");
//   }

//   try {
//     // Find the post containing the comment
//     const post = await PostModel.findOneAndUpdate(
//       { _id: postId, "comments._id": commentId },
//       {
//         $set: { "comments.$.text": text }, // Update the text of the specific comment
//       },
//       { new: true, runValidators: true } // Return the updated document and validate fields
//     );

//     if (!post) {
//       throw new Error("Post or comment not found.");
//     }

//     // Find the updated comment for returning to the client
//     const updatedComment = post.comments.find((comment) => comment._id.toString() === commentId);
//     return updatedComment;
//   } catch (error) {
//     console.error("Error updating comment:", error);
//     throw new Error("An error occurred while updating the comment.");
//   }
// },
// Function to update the comment



























  

  
  
};

module.exports = userController;
