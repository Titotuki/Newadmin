const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const dotenv = require("dotenv");
const crypto = require("crypto");

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

// ================== MongoDB Connection ==================
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("MongoDB connected"))
.catch((err) => console.error("MongoDB error:", err));

// ================== Schema ==================
const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  resetToken: String,
  resetTokenExpiry: Date,
});

const Admin = mongoose.model("Admin", adminSchema);

// ================== JWT Middleware ==================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Token required" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
};

// ================== OTP Store (in-memory) ==================
const otpStore = new Map();
const generateOTP = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

// ================== Routes ==================

// Create default admin (run once)
(async () => {
  const email = "stonerva.com@gmail.com";
  const password = "admin123";
  const hashed = await bcrypt.hash(password, 10);

  const exists = await Admin.findOne({ email });
  if (!exists) {
    await Admin.create({ email, password: hashed });
    console.log("Default admin created:", email, password);
  }
})();

// Login -> Send OTP (console only)
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const admin = await Admin.findOne({ email });
  if (!admin) return res.status(400).json({ message: "Invalid credentials" });

  const match = await bcrypt.compare(password, admin.password);
  if (!match) return res.status(400).json({ message: "Invalid credentials" });

  const otp = generateOTP();
  otpStore.set(email, { otp, expires: Date.now() + 5 * 60 * 1000 });

  console.log(`📩 OTP for ${email}: ${otp} (valid 5 mins)`);

  res.json({ message: "OTP generated. Check your console.", email });
});

// Verify OTP -> Return JWT
app.post("/api/verify-otp", async (req, res) => {
  const { email, otp } = req.body;

  const stored = otpStore.get(email);
  if (!stored || stored.expires < Date.now()) {
    return res.status(400).json({ message: "OTP expired or not found" });
  }

  if (stored.otp !== otp) {
    return res.status(400).json({ message: "Invalid OTP" });
  }

  otpStore.delete(email);

  const admin = await Admin.findOne({ email });
  const token = jwt.sign(
    { id: admin._id, email: admin.email },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.json({ token });
});

// Forgot Password -> Print reset link in console
app.post("/api/forgot-password", async (req, res) => {
  const { email } = req.body;

  const admin = await Admin.findOne({ email });
  if (!admin) return res.status(400).json({ message: "Email not found" });

  const resetToken = crypto.randomBytes(32).toString("hex");
  admin.resetToken = resetToken;
  admin.resetTokenExpiry = Date.now() + 15 * 60 * 1000; // 15 min
  await admin.save();

  const resetLink = `http://localhost:5000/reset-password.html?token=${resetToken}&email=${email}`;
  console.log(` Password reset link for ${email}: ${resetLink}`);

  res.json({ message: "Password reset link generated. Check your console." });
});

// Reset Password
app.post("/api/reset-password", async (req, res) => {
  const { email, token, newPassword } = req.body;

  const admin = await Admin.findOne({ email });
  if (
    !admin ||
    admin.resetToken !== token ||
    admin.resetTokenExpiry < Date.now()
  ) {
    return res.status(400).json({ message: "Invalid or expired token" });
  }

  admin.password = await bcrypt.hash(newPassword, 10);
  admin.resetToken = undefined;
  admin.resetTokenExpiry = undefined;
  await admin.save();

  res.json({ message: "Password reset successful" });
});

// Dashboard (protected)
app.get("/api/dashboard", authenticateToken, (req, res) => {
  res.json({ message: `Welcome ${req.user.email}` });
});

// ================== Start Server ==================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
