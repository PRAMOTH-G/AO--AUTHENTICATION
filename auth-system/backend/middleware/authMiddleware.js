const jwt = require("jsonwebtoken");
const User = require("../models/User");

// ================= PROTECT ROUTE =================
exports.protect = async (req, res, next) => {
  let token;

  // Check if Authorization header exists and starts with Bearer
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  }

  if (!token) {
    return res.status(401).json({ message: "No token, authorization denied" });
  }

  try {
    // Verify JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Attach user to request object, exclude password
    req.user = await User.findById(decoded.id).select("-password");

    // Call next middleware/route
    next();
  } catch (error) {
    res.status(401).json({ message: "Token invalid" });
  }
};

// ================= ADMIN ONLY =================
exports.adminOnly = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ message: "Authorization required" });
  }

  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin access only" });
  }

  next();
};
