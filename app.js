const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const dotenv = require("dotenv");
const bodyParser = require("body-parser");
const SibApiV3Sdk = require('sib-api-v3-sdk');

dotenv.config();
const app = express();
app.use(cors({
  origin: "http://localhost:5173",  // Allow requests from Vite dev server
  credentials: true
}));
app.use(bodyParser.json());

// MySQL connection setup
const getDb = async () => {
  return await mysql.createConnection({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: { rejectUnauthorized: true }
  });
};

// OTP Configuration
const OTP_EXPIRY_TIME = 300000; // 5 minutes
let otpStore = {}; // Use DB in production

// Generate a 6-digit OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Configure Brevo
const brevoClient = SibApiV3Sdk.ApiClient.instance;
const apiKey = brevoClient.authentications['api-key'];
apiKey.apiKey = process.env.BREVO_API_KEY; // from .env

const transactionalEmailApi = new SibApiV3Sdk.TransactionalEmailsApi();

// Route: Send OTP
app.post("/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email is required" });

  const otp = generateOTP();
  const expiration = Date.now() + OTP_EXPIRY_TIME;
  otpStore[email] = { otp, expiration };

  const sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
  sendSmtpEmail.sender = { name: "TakeYourTicket", email: "takeyourticketofficial@gmail.com" };
  sendSmtpEmail.to = [{ email }];
  sendSmtpEmail.subject = "Your OTP Code";
  sendSmtpEmail.htmlContent = `<p>Your OTP is: <strong>${otp}</strong>. It is valid for 5 minutes.</p>`;

  try {
    await transactionalEmailApi.sendTransacEmail(sendSmtpEmail);
    res.status(200).json({ message: "OTP sent successfully!" });
  } catch (error) {
    console.error("Brevo error:", error?.response?.body || error.message);
    res.status(500).json({ error: "Failed to send OTP" });
  }
});

// Route: Verify OTP
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  const storedOtp = otpStore[email];

  if (!storedOtp) return res.status(400).json({ error: "OTP not found for this email" });
  if (storedOtp.otp !== otp) return res.status(400).json({ error: "Invalid OTP" });
  if (Date.now() > storedOtp.expiration) return res.status(400).json({ error: "OTP expired" });

  delete otpStore[email];
  res.status(200).json({ message: "OTP verified successfully" });
});

// Signup
app.post("/signup", async (req, res) => {
  const { name, email, phone_number, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: "Name, Email & Password required" });
  }

  try {
    const db = await getDb();
    const [existing] = await db.execute("SELECT * FROM users WHERE email = ?", [email]);
    if (existing.length > 0) return res.status(409).json({ error: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.execute(
      "INSERT INTO users (name, email, phone_number, password) VALUES (?, ?, ?, ?)",
      [name, email, phone_number || "", hashedPassword]
    );

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Signup failed" });
  }
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: "Email and password required" });

  try {
    const db = await getDb();
    const [users] = await db.execute("SELECT * FROM users WHERE email = ?", [email]);

    if (users.length === 0)
      return res.status(401).json({ error: "User not found" });

    const isMatch = await bcrypt.compare(password, users[0].password);
    if (!isMatch) return res.status(401).json({ error: "Incorrect password" });

    res.status(200).json({ message: "Login successful", user: { name: users[0].name, email: users[0].email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});


let purchases = []; 

app.post("/api/purchase", async (req, res) => {
  const {
    purchase_id,
    user_id,
    course_id,
    purchase_date,
    price,
    course_name,
    razorpay_payment_id
  } = req.body;

  if (
    !purchase_id || !user_id || !course_id ||
    !purchase_date || !price || !course_name || !razorpay_payment_id
  ) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const query = `
    INSERT INTO course_purchases 
    (purchase_id, user_id, course_id, purchase_date, price, course_name, razorpay_payment_id)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `;

  try {
    const db = await getDb();
    await db.execute(query, [
      purchase_id,
      user_id,
      course_id,
      purchase_date,
      price,
      course_name,
      razorpay_payment_id
    ]);
    res.status(201).json({ message: "Purchase saved successfully" });
  } catch (err) {
    console.error("DB Error:", err);
    res.status(500).json({ error: "Failed to save purchase" });
  }
});



app.post("/api/request-callback", async (req, res) => {
  const { name, email, phone, country, occupation, state, language } = req.body;

  const query = `
    INSERT INTO callback_requests 
    (name, email, phone, country, occupation, state, language) 
    VALUES (?, ?, ?, ?, ?, ?, ?)`;

  try {
    const db = await getDb(); // <- await to get the connection
    await db.execute(query, [name, email, phone, country, occupation, state, language]);
    res.status(200).json({ message: "Request submitted successfully!" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error saving request" });
  }
});


// Server listener
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
