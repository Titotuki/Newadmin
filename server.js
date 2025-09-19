const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const dotenv = require("dotenv");
const crypto = require("crypto");
const path = require("path");
const { Resend } = require("resend");

dotenv.config();
const resend = new Resend(process.env.RESEND_API_KEY);
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



// Serve static files (index.html, CSS, JS)
app.use(express.static(path.join(__dirname, "public")));

// Fallback: if no route matches, send index.html
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ================== JWT Middleware ==================
// const authenticateToken = (req, res, next) => {
//   const authHeader = req.headers["authorization"];
//   console.log(authHeader);
  
//   const token = authHeader && authHeader.split(" ")[1];
//   if (!token) return res.status(401).json({ message: "Token required" });

//   jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
//     if (err) return res.status(403).json({ message: "Invalid token" });
//     req.user = user;
//     next();
//   });
// };

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
  const email = "titotuktuki@gmail.com";
  const password = "admin123";
  const hashed = await bcrypt.hash(password, 10);

  const exists = await Admin.findOne({ email });
  if (!exists) {
    await Admin.create({ email, password: hashed });
    console.log("Default admin created:", email, password);
  }
})();

// Login -> Send OTP (console only)
// app.post("/api/login", async (req, res) => {
//   const { email, password } = req.body;

//   const admin = await Admin.findOne({ email });
//   if (!admin) return res.status(400).json({ message: "Invalid credentials" });

//   const match = await bcrypt.compare(password, admin.password);
//   if (!match) return res.status(400).json({ message: "Invalid credentials" });

//   const otp = generateOTP();
//   otpStore.set(email, { otp, expires: Date.now() + 5 * 60 * 1000 });

//   console.log(`📩 OTP for ${email}: ${otp} (valid 5 mins)`);

//   res.json({ message: "OTP generated. Check your console.", email });
// });

// // Verify OTP -> Return JWT
// app.post("/api/verify-otp", async (req, res) => {
//   const { email, otp } = req.body;

//   const stored = otpStore.get(email);
//   if (!stored || stored.expires < Date.now()) {
//     return res.status(400).json({ message: "OTP expired or not found" });
//   }

//   if (stored.otp !== otp) {
//     return res.status(400).json({ message: "Invalid OTP" });
//   }

//   otpStore.delete(email);

//   const admin = await Admin.findOne({ email });
//   const token = jwt.sign(
//     { id: admin._id, email: admin.email },
//     process.env.JWT_SECRET,
//     { expiresIn: "1h" }
//   );

//   res.json({ token });
// });

// // Forgot Password -> Print reset link in console
// app.post("/api/forgot-password", async (req, res) => {
//   const { email } = req.body;

//   const admin = await Admin.findOne({ email });
//   if (!admin) return res.status(400).json({ message: "Email not found" });

//   const resetToken = crypto.randomBytes(32).toString("hex");
//   admin.resetToken = resetToken;
//   admin.resetTokenExpiry = Date.now() + 15 * 60 * 1000; // 15 min
//   await admin.save();

//   const resetLink = `http://localhost:5000/reset-password.html?token=${resetToken}&email=${email}`;
//   console.log(` Password reset link for ${email}: ${resetLink}`);

//   res.json({ message: "Password reset link generated. Check your console." });
// });

// // Reset Password
// app.post("/api/reset-password", async (req, res) => {
//   const { email, token, newPassword } = req.body;

//   const admin = await Admin.findOne({ email });
//   if (
//     !admin ||
//     admin.resetToken !== token ||
//     admin.resetTokenExpiry < Date.now()
//   ) {
//     return res.status(400).json({ message: "Invalid or expired token" });
//   }

//   admin.password = await bcrypt.hash(newPassword, 10);
//   admin.resetToken = undefined;
//   admin.resetTokenExpiry = undefined;
//   await admin.save();

//   res.json({ message: "Password reset successful" });
// });

// ================== Login -> Send OTP (via Resend) ==================
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const admin = await Admin.findOne({ email });
    console.log(admin);
    if (!admin) return res.status(400).json({ error: "User not found" });

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = Date.now() + 5 * 60 * 1000; // 5 minutes
    otpStore.set(email, { otp, expires: expiry });

    console.log(`Generated OTP for ${email}: ${otp}`);

    // ✅ Send OTP email
    const mail = await resend.emails.send({
      from: process.env.RESEND_FROM, // onboarding@resend.dev
      to: email,                     // user’s login email
      subject: "Your Login OTP",
      html: `
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="font-family: Arial, sans-serif; background-color:#f9f9f9; padding:20px;">
  <tr>
    <td align="center">
      <table width="600" cellpadding="0" cellspacing="0" border="0" style="background:#ffffff; border-radius:8px; overflow:hidden; box-shadow:0 2px 8px rgba(0,0,0,0.1);">
        <tr>
          <td style="padding:20px; text-align:center; background:#4a90e2; color:#fff; font-size:20px; font-weight:bold;">
           
          </td>
        </tr>
        <tr>
          <td style="padding:30px; font-size:16px; color:#333;">
            <p>Hi,</p>
            <p>Welcome! Please use the verification code below to complete your account setup.</p>
            <table width="100%" cellpadding="10" cellspacing="0" border="0" style="margin:20px 0;">
              <tr>
                <td align="center" style="background:#f4f4f4; border:1px solid #ddd; font-size:24px; font-weight:bold; letter-spacing:4px;">
                  ${otp}
                </td>
              </tr>
            </table>
            <p>This code will expire in <b>5 minutes</b>.</p>
            <p style="color:#d9534f; font-weight:bold;">⚠️ Do not share your OTP with anyone under any circumstances.</p>
          </td>
        </tr>
       
      </table>
    </td>
  </tr>
</table>

 
     
      `,
    });

    console.log("Resend API response:", mail);

    res.json({ message: "OTP sent to email" });
  }  catch (err) {
  console.error("Resend error details:", err);
  if (err.response) {
    console.error("Resend response error:", err.response.body);
  }
  res.status(500).json({ error: err.message || "Unknown error" });
}

});

// ================== Verify OTP -> Return JWT ==================
app.post("/api/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;

    const stored = otpStore.get(email);
    if (!stored || stored.expires < Date.now()) {
      return res.status(400).json({ message: "OTP expired or not found" });
    }

    if (stored.otp !== otp) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    // ✅ OTP is correct → remove from store
    otpStore.delete(email);

    const admin = await Admin.findOne({ email });
    if (!admin) return res.status(400).json({ message: "User not found" });

    // Generate JWT
    const token = jwt.sign(
      { id: admin._id, email: admin.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ message: "OTP verified successfully", token });
  } catch (err) {
    console.error("Verify OTP error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/test-email", async (req, res) => {
  try {
    const data = await resend.emails.send({
      from: "onboarding@resend.dev",   // must be this in free plan
      to: "titotuktuki@gmail.com",      // your email
      subject: "Test Email",
      html: "<p>Hello from Resend!</p>",
    });
    res.json(data);
  } catch (err) {
    console.error("Test email error:", err);
    res.status(500).json({ error: err.message });
  }
});
// ================== Forgot Password -> Send Reset Link (via Resend) ==================
app.post("/api/forgot-password", async (req, res) => {
  const { email } = req.body;

  const admin = await Admin.findOne({ email });
  if (!admin) return res.status(400).json({ message: "Email not found" });

  const resetToken = crypto.randomBytes(32).toString("hex");
  admin.resetToken = resetToken;
  admin.resetTokenExpiry = Date.now() + 15 * 60 * 1000; // 15 min
  await admin.save();

  const resetLink = `http://localhost:5000/reset-password.html?token=${resetToken}&email=${email}`;

  try {
    // ✅ Send password reset email
    await resend.emails.send({
      from: process.env.RESEND_FROM,
      to: email,
      subject: "Password Reset Request",
      html: `<p>Click below to reset your password:</p>
             <p><a href="${resetLink}">${resetLink}</a></p>
             <p>This link will expire in 15 minutes.</p>`,
    });

    res.json({ message: "Password reset link sent to your email." });
  } catch (err) {
    console.error("Resend error:", err);
    res.status(500).json({ message: "Failed to send reset link" });
  }
});

app.post("/api/reset-password", async (req, res) => {
  try {
    const { email, token, newPassword } = req.body;

    const admin = await Admin.findOne({ email });
    if (!admin) return res.status(400).json({ message: "User not found" });

    // Validate token + expiry
    if (
      !admin.resetToken ||
      admin.resetToken !== token ||
      admin.resetTokenExpiry < Date.now()
    ) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    // Hash new password
    admin.password = await bcrypt.hash(newPassword, 10);
    admin.resetToken = undefined;
    admin.resetTokenExpiry = undefined;
    await admin.save();

    res.json({ message: "Password reset successful. Please login again." });
  } catch (err) {
    console.error("Reset Password Error:", err);
    res.status(500).json({ message: "Failed to reset password" });
  }
});

// Dashboard (protected)
app.get("/api/dashboard", authenticateToken, (req, res) => {
  res.json({ message: `Welcome ${req.user.email}` });
});

// ================== Start Server ==================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
