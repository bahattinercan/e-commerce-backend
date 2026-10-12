const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { Product, Users, createEmptyCart } = require("./models");
require("dotenv").config();

const app = express();

// Only origins that actually talk to this API. In production set CORS_ORIGINS
// in .env: "https://shop.example.com,https://admin.example.com".
const allowedOrigins = (process.env.CORS_ORIGINS || "http://localhost:3000,http://localhost:5173,http://localhost:5174,http://localhost:5199")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(express.json({ limit: "100kb" }));
app.use(
  cors({
    origin: (origin, callback) => {
      // No Origin header = curl/server-to-server request, not a browser page.
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      const error = new Error(`Origin ${origin} is not allowed by CORS`);
      error.status = 403;
      return callback(error);
    },
  })
);

// Uploaded files are served from /images: stop the browser from sniffing an
// uploaded file as HTML/JS.
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  next();
});

// Brute-force protection for the credential endpoints.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, errors: "Too many attempts, please try again later." },
});

const port = process.env.PORT || 4000;
const host = process.env.HOST || "http://localhost";
const mongoUri = process.env.MONGO_CONNECT;
const jwtToken = process.env.JWT_TOKEN;
const tokenExpiry = process.env.JWT_EXPIRES_IN || "7d";

// Fail fast with a readable message instead of crashing later with a cryptic error.
if (!mongoUri) {
  console.error("Missing MONGO_CONNECT in .env (see .env.example)");
  process.exit(1);
}
if (!jwtToken) {
  console.error("Missing JWT_TOKEN in .env (see .env.example)");
  process.exit(1);
}

// Absolute path: multer/express.static must not depend on the process CWD.
const uploadDir = path.join(__dirname, "upload", "images");
fs.mkdirSync(uploadDir, { recursive: true });

// Wraps async route handlers so rejected promises reach the error middleware
// instead of becoming unhandled rejections / hanging requests.
const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const BCRYPT_ROUNDS = 10;
// $2a$ / $2b$ / $2y$ prefixes are bcrypt hashes; anything else is a legacy
// plaintext password written before hashing was introduced.
const isBcryptHash = (value) => typeof value === "string" && /^\$2[aby]\$\d{2}\$/.test(value);

// Database connection with MongoDB
mongoose
  .connect(mongoUri)
  .then(() => console.log("Connected to MongoDB"))
  .catch((error) => {
    console.error("MongoDB connection error:", error.message);
    process.exit(1);
  });

//#region  Middleware
const fetchUser = (req, res, next) => {
  const token = req.header("auth-token");

  if (!token) {
    return res.status(401).json({ success: false, errors: "Please authenticate using valid token!" });
  }

  try {
    const data = jwt.verify(token, jwtToken);
    req.user = data.user;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, errors: "Token is not valid!" });
  }
};

// The role is read from the database on every request (not from the token), so
// promoting/demoting a user takes effect without forcing a new login.
const requireAdmin = asyncHandler(async (req, res, next) => {
  const user = await Users.findById(req.user.id);

  if (!user) {
    return res.status(401).json({ success: false, errors: "User not found" });
  }

  if (user.role !== "admin") {
    return res.status(403).json({ success: false, errors: "Admin access required" });
  }

  req.adminUser = user;
  next();
});
//#endregion

// api creation
app.get("/", (req, res) => {
  res.send("Express App is Running!!!");
});

// image storage engine
// Extension comes from the verified mimetype, never from the client-supplied
// originalname (an attacker can name a file "payload.html.png").
const ALLOWED_IMAGE_TYPES = {
  "image/jpeg": ".jpg",
  "image/png": ".png",
  "image/webp": ".webp",
  "image/gif": ".gif",
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const extension = ALLOWED_IMAGE_TYPES[file.mimetype] || ".bin";
    return cb(null, `${file.fieldname}_${Date.now()}${extension}`);
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!ALLOWED_IMAGE_TYPES[file.mimetype]) {
      const error = new Error("Only JPEG, PNG, WebP or GIF images are allowed");
      error.status = 400;
      return cb(error);
    }
    return cb(null, true);
  },
});

// creating upload endpoint for images
app.use("/images", express.static(uploadDir));

app.post(
  "/upload",
  fetchUser,
  requireAdmin,
  upload.single("product"),
  asyncHandler(async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ success: 0, error: "No image file provided" });
    }
    res.json({
      success: 1,
      image_url: `${host}:${port}/images/${req.file.filename}`,
    });
  })
);

//#region Product Functions

app.get("/adminVerify", fetchUser, requireAdmin, (req, res) => {
  res.json({ success: true, name: req.adminUser.name, email: req.adminUser.email });
});

app.post(
  "/addProduct",
  fetchUser,
  requireAdmin,
  asyncHandler(async (req, res) => {
    const { name, image, category, new_price, old_price } = req.body;

    if (!name || !image || !category || new_price == null || old_price == null) {
      return res.status(400).json({ success: false, error: "Missing required product fields" });
    }

    // Use the highest existing id, not the last document of an unsorted find()
    // (otherwise ids repeat after the newest product is deleted).
    const lastProduct = await Product.findOne().sort({ id: -1 });
    const lastId = lastProduct ? lastProduct.id + 1 : 1;

    const product = new Product({
      id: lastId,
      name: name,
      image: image,
      category: category,
      new_price: new_price,
      old_price: old_price,
    });

    await product.save();
    res.json({ success: true, name: product.name });
  })
);

// Creating api for deleting products
app.post(
  "/removeProduct",
  fetchUser,
  requireAdmin,
  asyncHandler(async (req, res) => {
    const { id, name } = req.body;
    const productId = Number(id);

    if (!Number.isFinite(productId)) {
      return res.status(400).json({ success: false, error: "Invalid product id" });
    }

    const deleted = await Product.findOneAndDelete({ id: productId });
    if (!deleted) {
      return res.status(404).json({ success: false, error: "Product not found" });
    }

    console.log("Removed");
    res.json({ success: true, name: name });
  })
);

// Creating api for getting all products
app.get(
  "/allProducts",
  asyncHandler(async (req, res) => {
    const products = await Product.find({});
    res.json(products);
  })
);

app.get(
  "/newCollections",
  asyncHandler(async (req, res) => {
    const products = await Product.find({});
    const newCollection = products.slice(1).slice(-8);
    res.status(200).json(newCollection);
  })
);

app.get(
  "/popularInWomen",
  asyncHandler(async (req, res) => {
    const products = await Product.find({ category: "women" });
    const newCollection = products.slice(0, 4);
    res.status(200).json(newCollection);
  })
);

//#endregion

//#region Cart Functions
app.post(
  "/addToCart",
  fetchUser,
  asyncHandler(async (req, res) => {
    const { id } = req.user;
    const itemId = Number(req.body.itemId);

    if (!Number.isInteger(itemId) || itemId < 0) {
      return res.status(400).json({ success: false, errors: "Invalid item id" });
    }

    const userData = await Users.findById(id);
    if (!userData) {
      return res.status(404).json({ success: false, errors: "User not found" });
    }

    const cartData = userData.cartData || {};
    cartData[itemId] = (cartData[itemId] || 0) + 1;

    await Users.findByIdAndUpdate(id, { cartData });
    res.status(200).json({ success: true, message: "Added" });
  })
);

app.post(
  "/removeFromCart",
  fetchUser,
  asyncHandler(async (req, res) => {
    const { id } = req.user;
    const itemId = Number(req.body.itemId);

    if (!Number.isInteger(itemId) || itemId < 0) {
      return res.status(400).json({ success: false, errors: "Invalid item id" });
    }

    const userData = await Users.findById(id);
    if (!userData) {
      return res.status(404).json({ success: false, errors: "User not found" });
    }

    const cartData = userData.cartData || {};
    if ((cartData[itemId] || 0) > 0) {
      cartData[itemId] -= 1;
    }

    await Users.findByIdAndUpdate(id, { cartData });
    res.status(200).json({ success: true, message: "Removed" });
  })
);

app.post(
  "/getCart",
  fetchUser,
  asyncHandler(async (req, res) => {
    const { id } = req.user;

    if (!id) {
      return res.status(200).json({});
    }

    const userData = await Users.findById(id);
    if (!userData) {
      return res.status(404).json({ success: false, errors: "User not found" });
    }

    res.status(200).json(userData.cartData || {});
  })
);

//#endregion

//#region User Functions
app.post(
  "/signup",
  authLimiter,
  asyncHandler(async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ success: false, errors: "Username, email and password are required!" });
    }

    const check = await Users.findOne({ email: email });
    if (check) {
      return res.status(400).json({ success: false, errors: "This email is already in use!" });
    }

    const user = new Users({
      name: username,
      email: email,
      password: await bcrypt.hash(password, BCRYPT_ROUNDS),
      cartData: createEmptyCart(),
    });

    await user.save();

    const data = { user: { id: user.id } };
    const token = jwt.sign(data, jwtToken, { expiresIn: tokenExpiry });
    res.status(200).json({ success: true, token });
  })
);

app.post(
  "/login",
  authLimiter,
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, errors: "Email and password are required!" });
    }

    const user = await Users.findOne({ email: email });
    // Same answer for "no such user" and "wrong password" so the endpoint cannot
    // be used to enumerate which emails exist.
    if (!user) {
      return res.status(401).json({ success: false, errors: "Invalid email or password." });
    }

    const storedPassword = user.password || "";
    let passwordMatches = false;

    if (isBcryptHash(storedPassword)) {
      passwordMatches = await bcrypt.compare(password, storedPassword);
    } else {
      // Legacy plaintext record: verify it, then transparently upgrade to a hash.
      passwordMatches = storedPassword === password;
      if (passwordMatches) {
        user.password = await bcrypt.hash(password, BCRYPT_ROUNDS);
        await user.save();
        console.log(`Upgraded legacy password hash for ${user.email}`);
      }
    }

    if (!passwordMatches) {
      return res.status(401).json({ success: false, errors: "Invalid email or password." });
    }

    const data = { user: { id: user.id } };
    const token = jwt.sign(data, jwtToken, { expiresIn: tokenExpiry });
    res.json({ success: true, token });
  })
);
//#endregion

// 404 for unknown routes
app.use((req, res) => {
  res.status(404).json({ success: false, error: `Route not found: ${req.method} ${req.originalUrl}` });
});

// Central error handler: always answers with JSON instead of hanging the request.
// Middleware such as body-parser/multer attach a client-error status; honour it
// (malformed JSON must be 400, not 500) and only 5xx are logged as unhandled.
app.use((error, req, res, next) => {
  if (res.headersSent) {
    return next(error);
  }

  const status = error.name === "MulterError" ? 400 : Number(error.statusCode || error.status) || 500;

  if (status >= 500) {
    console.error("Unhandled error:", error);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }

  console.warn(`Request error (${status}):`, error.message);
  res.status(status).json({ success: false, error: error.message });
});

const server = app.listen(port, () => {
  console.log("Server Running on Port " + port);
});

server.on("error", (error) => {
  console.error("Server error:", error.message);
  process.exit(1);
});
