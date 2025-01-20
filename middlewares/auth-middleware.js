const jwt = require("jsonwebtoken");
const UserModel = require("../models/user");

const checkUserAuth = async (req, res, next) => {
  try {
    // Extract token from Authorization header (Bearer <token>)
    const token = req.headers.authorization?.split(" ")[1];
    
    if (!token) {
      return res.status(401).send({
        status: "failed",
        message: "Unauthorized access: Token missing",
      });
    }

    // Check if JWT_SECRET is defined in environment variables
    const jwtSecret = process.env.JWT_PRIVATE_KEY;
    if (!jwtSecret) {
      return res.status(500).send({
        status: "failed",
        message: "Server error: Missing JWT secret key",
      });
    }

    // Verify the token with the JWT secret
    const decoded = jwt.verify(token, jwtSecret);

    // Decode the token to extract the user ID
    if (!decoded || !decoded.id) {
      return res.status(401).send({
        status: "failed",
        message: "Invalid token structure",
      });
    }

    // Find the user in the database using the decoded user ID (exclude password)
    const user = await UserModel.findById(decoded.id).select("-password");

    // If user not found, respond with 404
    if (!user) {
      return res.status(404).send({
        status: "failed",
        message: "User not found",
      });
    }

    // Attach the user object to the request object (req.user) for later use in other routes
    req.user = user;

    // Proceed to the next middleware or route handler
    return next();
  } catch (error) {
    console.error("Auth middleware error:", error);

    // Handle specific JWT errors (e.g., invalid token, expired token)
    if (error.name === "JsonWebTokenError") {
      return res.status(401).send({
        status: "failed",
        message: "Invalid or expired token",
      });
    }

    // Handle other unexpected errors
    return res.status(401).send({
      status: "failed",
      message: "Unauthorized access: " + error.message,
    });
  }
};

module.exports = { checkUserAuth };
