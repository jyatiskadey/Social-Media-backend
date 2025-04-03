require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const path = require("path");
const connectDB = require("./config/connectdb");
const userRoutes = require("./routes/userRoutes");
const port = 9874;
const app = express();

connectDB();

app.use(bodyParser.json());
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Home route (Render index.ejs)
app.get("/", (req, res) => {
  res.render("index");
});
app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/profile", (req, res) => {
  res.render("profile");
});

// API routes
app.use("/api/posts", userRoutes);

// Start the server
app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
console.log('JWT Secret:', process.env.JWT_PRIVATE_KEY); // Debugging