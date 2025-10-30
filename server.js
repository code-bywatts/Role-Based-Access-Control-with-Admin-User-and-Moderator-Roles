import express from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();
const app = express();
app.use(express.json());

// Hardcoded users with roles
const users = [
  { username: "admin", password: "admin123", role: "Admin" },
  { username: "john", password: "user123", role: "User" },
  { username: "sara", password: "mod123", role: "Moderator" },
];

// Login route (issues JWT token)
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  if (!user) return res.status(401).json({ message: "Invalid credentials" });

  const token = jwt.sign(
    { username: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.json({ message: "Login successful", token });
});

// Middleware to verify JWT
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token)
    return res.status(403).json({ message: "Access denied. Token missing." });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Invalid or expired token." });
    req.user = decoded;
    next();
  });
}

// Middleware to check user roles
function authorizeRoles(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role))
      return res.status(403).json({ message: "Access forbidden: insufficient role privileges." });
    next();
  };
}

// Routes for different roles
app.get("/", (req, res) => res.send("Role-Based Access Control API Running..."));

// Protected route (any logged-in user)
app.get("/profile", verifyToken, (req, res) => {
  res.json({ message: `Welcome ${req.user.username}`, role: req.user.role });
});

// Admin-only route
app.get("/admin", verifyToken, authorizeRoles("Admin"), (req, res) => {
  res.json({ message: "Admin panel access granted." });
});

// Moderator-only route
app.get("/moderator", verifyToken, authorizeRoles("Moderator", "Admin"), (req, res) => {
  res.json({ message: "Moderator section access granted." });
});

// General user route
app.get("/user", verifyToken, authorizeRoles("User", "Admin", "Moderator"), (req, res) => {
  res.json({ message: "User dashboard access granted." });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
