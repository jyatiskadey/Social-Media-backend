const express = require("express");
const mongoose = require("mongoose");
const router = express.Router();
const multer = require("multer");
const fs = require("fs");
const cloudinary = require("cloudinary").v2;
// const { uploadImage } = require("../controllers/userController.js");
const PostModel = require("../models/post.js"); // Adjust the path as needed
const bodyParser = require('body-parser');
const cors = require('cors');
const nodemailer = require('nodemailer');
const Admin = require('../models/admin.js');


// Import user controller and middleware
const userController = require("../controllers/userController.js");
const { checkUserAuth } = require("../middlewares/auth-middleware.js");


const transporter = nodemailer.createTransport({
  service: 'gmail', // You can change this based on your email provider (e.g., SendGrid, Mailgun)
  auth: {
    user: 'somud744@gmail.com', // Your email address
    pass: 'jyatiska', // Your email password (or app-specific password if 2FA enabled)
  },
});

// Multer configuration for local file storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});

const upload = multer({ storage });

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Public Routes
router.post('/admin-register', userController.registerAdmin);
router.post("/register", userController.userRegistration); // Registration route

router.post("/login", userController.userLogin); // Login route
router.post('/admin/login',userController.adminLogin);



// Change password route (authentication required)
router.post("/changepassword", checkUserAuth, userController.changePassword);

// Get user details route (authentication required)
router.get("/user-details", checkUserAuth, userController.citizenUserDetails);

router.get("/user-post-details", checkUserAuth, userController.getUserPosts);


router.put("/:userId/toggle-status", userController.adminUserToggle);




router.delete('/delete-post/:postId',checkUserAuth, userController.deletePost);
router.put('/edit-post/:postId', userController.editPost);


// Get All Users
router.get('/getallusers',userController.getAllUsers)
router.get('/getallposts',userController.getAllPosts)
router.get('/active-user',userController.fetchActiveUsers)

router.get("/getpostbyID/:id", userController.getPostByID);

router.post("/create-notification", userController.createNotification);

router.get("/get-all-notification",userController.getAllNotifications)
router.get("/see-all-posts",userController.seeAllPosts)
router.delete('/notifications/:id', userController.deleteNotification);

router.post("/send-msg",userController.sendMessageRoute)

router.get("/get-user-specific-notification",checkUserAuth,userController.getUserMessagesRoute)
router.get("/get-all-msg",userController.getAllMessagesRoute);

router.post("/:postId/add-comment", checkUserAuth,userController.addComment);

// router.post("/:postId/update-comment", checkUserAuth,userController.updateComment);


router.get("/:postId/comments", checkUserAuth, userController.getComments);

router.get("/:postId/Allcomments", checkUserAuth, userController.getAllComments);

// router.put("/:postId/:commentId/UpdateComment",checkUserAuth,userController.updateCommentText);

// PUT route to update a comment

router.put("/:postId/comments/:commentId/UpdateComment", checkUserAuth, async (req, res) => {
  const { postId, commentId } = req.params;
  const { text } = req.body;
  const userId = req.user.id;

  // Validate input: Check if comment text is empty
  if (!text || text.trim() === "") {
    return res.status(400).json({ message: "Comment text cannot be empty." });
  }

  // Validate ObjectIds
  if (!mongoose.isValidObjectId(postId) || !mongoose.isValidObjectId(commentId) || !mongoose.isValidObjectId(userId)) {
    return res.status(400).json({ message: "Invalid postId, commentId, or userId." });
  }

  try {
    // Find the post and update the specific comment by matching postId, commentId, and userId
    const post = await PostModel.findOneAndUpdate(
      { 
        _id: new mongoose.Types.ObjectId(postId), 
        "comments._id": new mongoose.Types.ObjectId(commentId),
        "comments.userId": new mongoose.Types.ObjectId(userId) 
      },
      {
        $set: { "comments.$.text": text }, // Update the comment text
      },
      { new: true, runValidators: true } // Return the updated post
    );

    if (!post) {
      return res.status(404).json({ message: "Post or comment not found, or you are not authorized to edit this comment." });
    }

    // Find and return the updated comment
    const updatedComment = post.comments.find(comment => comment._id.toString() === commentId);
    
    // Send the response back to the client
    res.status(200).json({ message: "Comment updated successfully.", comment: updatedComment });
  } catch (error) {
    console.error("Error updating comment:", error);
    res.status(500).json({ message: error.message || "An error occurred while updating the comment." });
  }
});




















//========================= UPLOAD IMAGE ==========================
router.post("/upload-image", upload.single("image"), async (req, res) => {
  try {
    // Check if an image is uploaded
    if (!req.file) {
      return res.status(400).send({
        status: "failed",
        message: "No file uploaded. Please provide an image.",
      });
    }

    const filePath = req.file.path;

    // Upload the image to Cloudinary
    const result = await cloudinary.uploader.upload(filePath, {
      folder: "uploads", // Folder name in Cloudinary where the image will be saved
    });

    // Remove the file from local storage after upload
    fs.unlinkSync(filePath);

    // Send back the image URL from Cloudinary without saving to the database
    res.status(200).send({
      status: "success",
      message: "Image uploaded successfully",
      imageUrl: result.secure_url,  // Cloudinary URL
    });
  } catch (error) {
    console.error("Error uploading image:", error);
    if (req.file && req.file.path) {
      fs.unlinkSync(req.file.path); // Clean up local file if error occurs
    }
    res.status(500).send({
      status: "failed",
      message: "Failed to upload image",
    });
  }
});

//========================= UPLOAD IMAGE ==========================
router.post("/create-post", checkUserAuth, async (req, res) => {
  try {
    // Check if the user is authenticated
    if (!req.user || !req.user._id) {
      return res.status(400).json({ success: false, message: "User not authenticated." });
    }

    const userId = req.user._id;
    const userName = req.user.name;

    // Extract title, description, and imageUrl from the request body
    const { title, description, imageUrl } = req.body;

    // Validate that title, description, and imageUrl are provided
    if (!title || !description || !imageUrl) {
      return res.status(400).json({
        success: false,
        message: "Title, description, and image URL are required.",
      });
    }

    // Create a new post with the provided data
    const newPost = new PostModel({
      title,
      description,
      userId,
      userName,
      imageUrl,
    });

    // Save the new post to the database
    await newPost.save();

    // Send the newly created post as a response
    res.status(201).json({ success: true, post: newPost });
  } catch (error) {
    console.error("Error creating post:", error);
    res.status(500).json({ success: false, message: "Error creating post" });
  }
});

// Route to send email
router.post('/api/send-email', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Email is required.' });
  }

  try {
    // Find user by email in the database
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    // Generate a reset password token (expires in 1 hour)
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Create a reset link that includes the token as a query parameter
    const resetLink = `http://localhost:3000/reset-password?token=${token}`;

    // Send email with reset link
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset Request',
      text: `You requested a password reset. Click the link below to reset your password:\n\n${resetLink}`,
    };

    await transporter.sendMail(mailOptions);

    // Send response
    res.status(200).json({ message: 'Password reset link sent to your email.' });

  } catch (error) {
    console.error('Error sending email:', error);
    res.status(500).json({ message: 'Failed to send reset link.' });
  }
});


router.post("/:postId/add-comment", async (req, res) => {
  const { postId } = req.params; // Extract postId from URL params
  const { comment } = req.body; // Extract comment from the request body

  if (!comment || comment.trim() === "") {
    return res.status(400).json({ message: "Comment cannot be empty!" });
  }

  try {
    // Find the post by ID
    const post = await Post.findById(postId);

    if (!post) {
      return res.status(404).json({ message: "Post not found!" });
    }

    // Add the comment to the post's comments array
    post.comments.push({ text: comment, createdAt: new Date() });

    // Save the updated post
    await post.save();

    res.status(200).json({ message: "Comment added successfully!" });
  } catch (error) {
    console.error("Error adding comment:", error);
    res.status(500).json({ message: "An error occurred while adding the comment." });
  }
});








module.exports = router;
