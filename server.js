require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const multer = require("multer");

const validator = require("validator");

const {
  parsePhoneNumberFromString
} = require("libphonenumber-js");

const cloudinary = require("cloudinary").v2;

const {
  CloudinaryStorage
} = require("multer-storage-cloudinary");

/* =========================
   APP
========================= */

const app = express();

/* =========================
   GLOBAL STATUS
========================= */

let mongoStatus = false;
let cloudinaryStatus = false;

/* =========================
   SECURITY MIDDLEWARE
========================= */

app.use(cors());

app.use(express.json({
  limit: "10mb"
}));

app.use(helmet());

app.use(rateLimit({

  windowMs: 15 * 60 * 1000,

  max: 100,

  message: "Too many requests. Try again later."

}));

/* =========================
   ENV VALIDATION
========================= */

const requiredEnv = [

  "MONGO_URL",

  "JWT_SECRET",

  "CLOUDINARY_CLOUD_NAME",

  "CLOUDINARY_API_KEY",

  "CLOUDINARY_API_SECRET"

];

requiredEnv.forEach((key) => {

  if (!process.env[key]) {

    console.log(`Missing ENV: ${key}`);

    process.exit(1);

  }

});

/* =========================
   DATABASE
========================= */

mongoose.connect(process.env.MONGO_URL, {

  useNewUrlParser: true,

  useUnifiedTopology: true

})

.then(() => {

  mongoStatus = true;

  console.log("✅ MongoDB Connected");

})

.catch((err) => {

  mongoStatus = false;

  console.log("❌ MongoDB Error:");

  console.log(err);

});

/* =========================
   CLOUDINARY CONFIG
========================= */

cloudinary.config({

  cloud_name:
    process.env.CLOUDINARY_CLOUD_NAME,

  api_key:
    process.env.CLOUDINARY_API_KEY,

  api_secret:
    process.env.CLOUDINARY_API_SECRET

});

/* =========================
   VERIFY CLOUDINARY
========================= */

cloudinary.api.ping()

.then(() => {

  cloudinaryStatus = true;

  console.log("✅ Cloudinary Connected");

})

.catch((err) => {

  cloudinaryStatus = false;

  console.log("❌ Cloudinary Error");

  console.log(err);

});

/* =========================
   CLOUDINARY STORAGE
========================= */

const storage = new CloudinaryStorage({

  cloudinary,

  params: async (req, file) => ({

    folder: "marketplace",

    allowed_formats: [

      "jpg",
      "jpeg",
      "png",
      "webp"

    ],

    transformation: [

      {
        width: 1000,
        crop: "limit"
      }

    ]

  })

});

/* =========================
   MULTER
========================= */

const upload = multer({

  storage,

  limits: {
    fileSize: 5 * 1024 * 1024
  },

  fileFilter: (req, file, cb) => {

    const allowed = [

      "image/jpeg",
      "image/png",
      "image/webp"

    ];

    if (allowed.includes(file.mimetype)) {

      cb(null, true);

    } else {

      cb(new Error("Only image files allowed"));

    }

  }

});

/* =========================
   USER MODEL
========================= */

const userSchema = new mongoose.Schema({

  firstName: {
    type: String,
    trim: true,
    maxlength: 50,
    default: ""
  },

  lastName: {
    type: String,
    trim: true,
    maxlength: 50,
    default: ""
  },

  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },

  password: {
    type: String,
    required: true,
    minlength: 6
  },

  phone: {
    type: String,
    default: ""
  },

  country: {
    type: String,
    default: "Malawi"
  },

  location: {
    type: String,
    trim: true,
    default: ""
  },

  bio: {
    type: String,
    maxlength: 500,
    default: ""
  },

  avatar: {
    type: String,
    default: ""
  }

}, { timestamps: true });

const User = mongoose.model("User", userSchema);

/* =========================
   PRODUCT MODEL
========================= */

const productSchema = new mongoose.Schema({

  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },

  name: {
    type: String,
    required: true,
    trim: true
  },

  category: {
    type: String,
    required: true
  },

  currency: {
    type: String,
    enum: ["MWK", "USD"],
    default: "MWK"
  },

  price: {
    type: Number,
    required: true,
    min: 0
  },

  stock: {
    type: Number,
    default: 0
  },

  description: {
    type: String,
    default: ""
  },

  location: {
    type: String,
    default: ""
  },

  image: {
    type: String,
    default: ""
  }

}, { timestamps: true });

const Product = mongoose.model("Product", productSchema);

/* =========================
   JWT AUTH
========================= */

function auth(req, res, next) {

  const header =
    req.headers.authorization;

  if (!header) {

    return res.status(401).json({
      message: "No token provided"
    });

  }

  const token =
    header.split(" ")[1];

  try {

    const decoded =
      jwt.verify(
        token,
        process.env.JWT_SECRET
      );

    req.user = decoded;

    next();

  } catch (err) {

    return res.status(401).json({
      message: "Invalid token"
    });

  }

}

/* =========================
   HEALTH CHECK
========================= */

app.get("/", (req, res) => {

  res.json({

    success: true,

    server: "Running",

    mongodb: mongoStatus,

    cloudinary: cloudinaryStatus

  });

});

/* =========================
   STATUS API
========================= */

app.get("/api/status", (req, res) => {

  res.json({

    mongodb: mongoStatus,

    cloudinary: cloudinaryStatus

  });

});

/* =========================
   REGISTER
========================= */

app.post(
  "/api/auth/register",

  async (req, res) => {

    try {

      const {
        email,
        password
      } = req.body;

      if (!email || !password) {

        return res.status(400).json({
          message: "Email and password required"
        });

      }

      if (!validator.isEmail(email)) {

        return res.status(400).json({
          message: "Invalid email"
        });

      }

      if (password.length < 6) {

        return res.status(400).json({
          message: "Password must be at least 6 characters"
        });

      }

      const exists =
        await User.findOne({
          email
        });

      if (exists) {

        return res.status(400).json({
          message: "User already exists"
        });

      }

      const hashed =
        await bcrypt.hash(password, 10);

      await User.create({

        email,

        password: hashed

      });

      res.status(201).json({
        message: "Registered successfully"
      });

    } catch (err) {

      console.log(err);

      res.status(500).json({
        message: "Server error"
      });

    }

  });

/* =========================
   LOGIN
========================= */

app.post(
  "/api/auth/login",

  async (req, res) => {

    try {

      const {
        email,
        password
      } = req.body;

      const user =
        await User.findOne({
          email
        });

      if (!user) {

        return res.status(400).json({
          message: "User not found"
        });

      }

      const valid =
        await bcrypt.compare(
          password,
          user.password
        );

      if (!valid) {

        return res.status(400).json({
          message: "Invalid password"
        });

      }

      const token = jwt.sign({

        id: user._id,
        email: user.email

      },

        process.env.JWT_SECRET,

        {
          expiresIn: "7d"
        });

      const safeUser = {

        _id: user._id,

        firstName: user.firstName,

        lastName: user.lastName,

        email: user.email,

        avatar: user.avatar

      };

      res.json({

        token,

        user: safeUser

      });

    } catch (err) {

      console.log(err);

      res.status(500).json({
        message: "Server error"
      });

    }

  });

/* =========================
   GET PROFILE
========================= */

app.get(
  "/api/profile",
  auth,

  async (req, res) => {

    try {

      const user =
        await User.findById(
          req.user.id
        ).select("-password");

      res.json(user);

    } catch (err) {

      res.status(500).json({
        message: "Server error"
      });

    }

  });

/* =========================
   UPDATE PROFILE
========================= */

app.put(
  "/api/profile",
  auth,
  upload.single("avatar"),

  async (req, res) => {

    try {

      const rawPhone =
        req.body.phone?.trim();

      let finalPhone = "";

      if (rawPhone) {

        const phone =
          parsePhoneNumberFromString(
            rawPhone
          );

        if (!phone || !phone.isValid()) {

          return res.status(400).json({
            message: "Invalid phone number"
          });

        }

        finalPhone = phone.number;

      }

      const updateData = {

        firstName:
          req.body.firstName?.trim(),

        lastName:
          req.body.lastName?.trim(),

        phone: finalPhone,

        country:
          req.body.country,

        location:
          req.body.location?.trim(),

        bio:
          req.body.bio?.trim()

      };

      if (req.file) {

        updateData.avatar =
          req.file.path;

      }

      const updatedUser =
        await User.findByIdAndUpdate(

          req.user.id,

          updateData,

          { new: true }

        ).select("-password");

      res.json(updatedUser);

    } catch (err) {

      console.log(err);

      res.status(500).json({
        message: "Server error"
      });

    }

  });

/* =========================
   ADD PRODUCT
========================= */

app.post(
  "/api/products",
  auth,
  upload.single("image"),

  async (req, res) => {

    try {

      const {
        name,
        category,
        currency,
        price,
        stock,
        description,
        location
      } = req.body;

      if (!name) {

        return res.status(400).json({
          message: "Product name required"
        });

      }

      if (!price) {

        return res.status(400).json({
          message: "Price required"
        });

      }

      const product =
        await Product.create({

          userId: req.user.id,

          name: name.trim(),

          category,

          currency,

          price,

          stock,

          description,

          location,

          image:
            req.file ? req.file.path : ""

        });

      res.status(201).json(product);

    } catch (err) {

      console.log(err);

      res.status(500).json({
        message: "Server error"
      });

    }

  });

/* =========================
   GET MY PRODUCTS
========================= */

app.get(
  "/api/products/my",
  auth,

  async (req, res) => {

    try {

      const products =
        await Product.find({

          userId: req.user.id

        }).sort({

          createdAt: -1

        });

      res.json(products);

    } catch (err) {

      res.status(500).json({
        message: "Server error"
      });

    }

  });

/* =========================
   GET PUBLIC PRODUCTS
========================= */

app.get(
  "/api/products",

  async (req, res) => {

    try {

      const products =
        await Product.find()

          .sort({
            createdAt: -1
          })

          .populate(
            "userId",
            "firstName lastName avatar"
          );

      res.json(products);

    } catch (err) {

      res.status(500).json({
        message: "Server error"
      });

    }

  });

/* =========================
   UPDATE PRODUCT
========================= */

app.put(
  "/api/products/:id",
  auth,
  upload.single("image"),

  async (req, res) => {

    try {

      const updateData = {

        name: req.body.name,
        category: req.body.category,
        currency: req.body.currency,
        price: req.body.price,
        stock: req.body.stock,
        description: req.body.description,
        location: req.body.location

      };

      if (req.file) {

        updateData.image =
          req.file.path;

      }

      const updated =
        await Product.findOneAndUpdate(

          {

            _id: req.params.id,

            userId: req.user.id

          },

          updateData,

          { new: true }

        );

      if (!updated) {

        return res.status(404).json({
          message: "Product not found"
        });

      }

      res.json(updated);

    } catch (err) {

      res.status(500).json({
        message: "Server error"
      });

    }

  });

/* =========================
   DELETE PRODUCT
========================= */

app.delete(
  "/api/products/:id",
  auth,

  async (req, res) => {

    try {

      const deleted =
        await Product.findOneAndDelete({

          _id: req.params.id,

          userId: req.user.id

        });

      if (!deleted) {

        return res.status(404).json({
          message: "Product not found"
        });

      }

      res.json({
        message: "Product deleted successfully"
      });

    } catch (err) {

      res.status(500).json({
        message: "Server error"
      });

    }

  });

/* =========================
   GLOBAL ERROR HANDLER
========================= */

app.use((err, req, res, next) => {

  console.log(err);

  res.status(500).json({

    message:
      err.message || "Server Error"

  });

});

/* =========================
   SERVER
========================= */

const PORT =
  process.env.PORT || 5000;

app.listen(PORT, "0.0.0.0", () => {

  console.log(
    `✅ Server running on port ${PORT}`
  );

});