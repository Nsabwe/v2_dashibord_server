const express = require("express");
const path = require("path");
const mongoose = require("mongoose");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const dotenv = require("dotenv");
const cors = require("cors");
const streamifier = require("streamifier");
const jwt = require("jsonwebtoken");

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

const JWT_SECRET = process.env.JWT_SECRET || "mysecretkey";

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get("/", (req, res) => {
  res.send("API is running...");
});

/* ------------------ STATUS FLAGS ------------------ */
let mongoConnected = false;
let cloudinaryConnected = false;

/* ------------------ MONGOOSE ------------------ */
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    mongoConnected = true;
    console.log("MongoDB connected");
  })
  .catch(err => {
    mongoConnected = false;
    console.log(err);
  });

/* ------------------ CLOUDINARY ------------------ */
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// test cloudinary connection
cloudinary.api.ping()
  .then(() => {
    cloudinaryConnected = true;
    console.log("Cloudinary connected");
  })
  .catch(err => {
    cloudinaryConnected = false;
    console.log("Cloudinary error", err);
  });

/* ------------------ JWT MIDDLEWARE ------------------ */
function verifyToken(req, res, next) {
  const token = req.headers["authorization"];

  if (!token) return res.status(403).json({ message: "No token provided" });

  jwt.verify(token.split(" ")[1], JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Invalid token" });

    req.user = decoded;
    next();
  });
}

/* ------------------ SIMPLE LOGIN ------------------ */
app.post("/api/login", (req, res) => {
  const { name, phone } = req.body;

  if (!name || !phone) {
    return res.status(400).json({ message: "Missing data" });
  }

  const token = jwt.sign({ name, phone }, JWT_SECRET, { expiresIn: "7d" });

  res.json({ token });
});

/* ------------------ SCHEMAS ------------------ */
const UserSchema = new mongoose.Schema({
  name: String,
  phone: String,
  location: String,
  imageURL: String,
  isOnline: Boolean
});

const ProductSchema = new mongoose.Schema({
  name: String,
  category: String,
  priceMWK: Number,
  priceUSD: Number,
  phone: String,
  location: String,
  imageURL: String,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", UserSchema);
const Product = mongoose.model("Product", ProductSchema);

/* ------------------ MULTER ------------------ */
const upload = multer({ storage: multer.memoryStorage() });

/* ------------------ CLOUD UPLOAD ------------------ */
function uploadToCloudinary(fileBuffer) {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder: "ourmarket" },
      (error, result) => {
        if (error) return reject(error);
        resolve(result);
      }
    );

    streamifier.createReadStream(fileBuffer).pipe(stream);
  });
}

/* ------------------ STATUS ROUTE ------------------ */
app.get("/api/status", (req, res) => {
  res.json({
    mongoDB: mongoConnected,
    cloudinary: cloudinaryConnected
  });
});

/* ------------------ ROUTES ------------------ */

// GET PROFILE
app.get("/api/me", async (req, res) => {
  let user = await User.findOne();

  if (!user) {
    user = await User.create({
      name: "John Doe",
      phone: "+265000000000",
      location: "Lilongwe",
      imageURL: "https://via.placeholder.com/80",
      isOnline: true
    });
  }

  res.json(user);
});

// UPDATE PROFILE (JWT PROTECTED)
app.post("/api/me", verifyToken, upload.single("image"), async (req, res) => {
  try {
    let imageURL;

    if (req.file) {
      const result = await uploadToCloudinary(req.file.buffer);
      imageURL = result.secure_url;
    }

    const update = {
      name: req.body.name,
      phone: req.body.phone,
      location: req.body.location
    };

    if (imageURL) update.imageURL = imageURL;

    const user = await User.findOneAndUpdate({}, update, { new: true, upsert: true });

    res.json(user);
  } catch (err) {
    console.log(err);
    res.status(500).send("Error updating profile");
  }
});

/* ------------------ PRODUCTS (PROTECTED) ------------------ */

// ADD PRODUCT
app.post("/api/products", verifyToken, upload.single("image"), async (req, res) => {
  try {
    let imageURL = "";

    if (req.file) {
      const result = await uploadToCloudinary(req.file.buffer);
      imageURL = result.secure_url;
    }

    const product = await Product.create({
      name: req.body.name,
      category: req.body.category,
      priceMWK: req.body.priceMWK,
      priceUSD: req.body.priceUSD,
      phone: req.body.phone,
      location: req.body.location,
      imageURL
    });

    res.json(product);
  } catch (err) {
    console.log(err);
    res.status(500).send("Error adding product");
  }
});

// GET MY PRODUCTS
app.get("/api/my-products", verifyToken, async (req, res) => {
  const products = await Product.find().sort({ createdAt: -1 });
  res.json(products);
});

// DELETE PRODUCT
app.delete("/api/products/:id", verifyToken, async (req, res) => {
  await Product.findByIdAndDelete(req.params.id);
  res.json({ message: "Deleted" });
});

/* ------------------ START SERVER ------------------ */
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});