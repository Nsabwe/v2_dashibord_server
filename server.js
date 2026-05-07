require("dotenv").config();

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const cloudinary = require("cloudinary").v2;
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const multer = require("multer");

const app = express();

// ================= CONFIG =================
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

// ================= MIDDLEWARE =================
app.use(cors());
app.use(express.json());

// ================= CLOUDINARY CONFIG =================
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Upload directly to Cloudinary
const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "ourmarket",
    allowed_formats: ["jpg", "png", "jpeg", "webp"],
  },
});

const upload = multer({ storage });

// ================= MONGODB =================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(err));

// ================= SCHEMAS =================
const User = mongoose.model("User", new mongoose.Schema({
  email: String,
  password: String,
  name: String,
  phone: String,
  location: String,
  imageURL: String,
}));

const Product = mongoose.model("Product", new mongoose.Schema({
  userId: String,
  name: String,
  category: String,
  price: Number,
  currency: String,
  phone: String,
  location: String,
  imageURL: String,
  createdAt: { type: Date, default: Date.now }
}));

// ================= AUTH =================
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
}

// ================= LOGIN =================
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  let user = await User.findOne({ email });

  if (!user) {
    const hashed = await bcrypt.hash(password, 10);
    user = await User.create({ email, password: hashed });
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ message: "Wrong password" });

  const token = jwt.sign({ id: user._id }, JWT_SECRET);

  res.json({ token });
});

// ================= PROFILE =================
app.get("/api/me", auth, async (req, res) => {
  const user = await User.findById(req.user.id);
  res.json(user);
});

app.post("/api/me", auth, upload.single("image"), async (req, res) => {
  const { name, phone, location } = req.body;

  const update = {
    name,
    phone,
    location,
  };

  // Cloudinary gives secure_url automatically
  if (req.file) {
    update.imageURL = req.file.path;
  }

  const user = await User.findByIdAndUpdate(req.user.id, update, {
    new: true,
  });

  res.json(user);
});

// ================= PRODUCTS =================

// ADD PRODUCT (IMAGE → CLOUDINARY)
app.post("/api/products", auth, upload.single("image"), async (req, res) => {
  const { name, category, price, currency, phone, location } = req.body;

  const product = await Product.create({
    userId: req.user.id,
    name,
    category,
    price,
    currency,
    phone,
    location,
    imageURL: req.file ? req.file.path : "",
  });

  res.json(product);
});

// GET MY PRODUCTS
app.get("/api/my-products", auth, async (req, res) => {
  const products = await Product.find({ userId: req.user.id });
  res.json(products);
});

// DELETE PRODUCT
app.delete("/api/products/:id", auth, async (req, res) => {
  await Product.deleteOne({
    _id: req.params.id,
    userId: req.user.id,
  });

  res.json({ message: "Deleted" });
});

// UPDATE PRODUCT
app.put("/api/products/:id", auth, async (req, res) => {
  const product = await Product.findOneAndUpdate(
    { _id: req.params.id, userId: req.user.id },
    req.body,
    { new: true }
  );

  res.json(product);
});

// ================= START =================
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});