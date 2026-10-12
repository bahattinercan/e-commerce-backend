const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const { pipeline } = require("node:stream");
const { Product, Users, RefreshToken, createEmptyCart } = require("./models");
require("dotenv").config();

const app = express();

// Only origins that actually talk to this API. In production set CORS_ORIGINS
// in .env: "https://shop.example.com,https://admin.example.com".
const allowedOrigins = (process.env.CORS_ORIGINS || "http://localhost:3000,http://localhost:5173,http://localhost:5174,http://localhost:5199")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

// Auth is carried in an httpOnly cookie instead of localStorage: an XSS in the
// SPA cannot read the token. SameSite=strict stops a third-party page from
// making the browser send it (CSRF); Secure is enabled behind HTTPS.
// SameSite=strict is the safest default while the SPA and the API are on the
// same site. If the SPA is served from a *different* domain in production the
// browser will not send the cookie at all: set COOKIE_SAMESITE=none together
// with COOKIE_SECURE=true (Secure is mandatory for SameSite=None).
const cookieOptions = {
  httpOnly: true,
  sameSite: process.env.COOKIE_SAMESITE || "strict",
  secure: process.env.COOKIE_SECURE === "true",
};

// helmet: CSP, nosniff, X-Frame-Options, referrer policy, etc.
// crossOriginResourcePolicy must stay permissive: the storefront loads product
// images served by this API from a different dev port.
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        objectSrc: ["'none'"],
      },
    },
  })
);
app.use(express.json({ limit: "100kb" }));
app.use(cookieParser());
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
    credentials: true,
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
// The access token is short-lived; a separate httpOnly refresh cookie renews it
// so a stolen/leaked access token has a small window of usefulness.
const accessExpiresSec = Math.max(60, Number(process.env.JWT_ACCESS_EXPIRES_SEC || 900));
const refreshExpiresDays = Math.max(1, Number(process.env.REFRESH_TOKEN_DAYS || 7));

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
// Runtime uploads are gitignored; the demo images shipped with the repo live in
// seed/images so user uploads never end up in git.
const uploadDir = path.join(__dirname, "upload", "images");
const seedDir = path.join(__dirname, "seed", "images");
fs.mkdirSync(uploadDir, { recursive: true });

// Wraps async route handlers so rejected promises reach the error middleware
// instead of becoming unhandled rejections / hanging requests.
const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const BCRYPT_ROUNDS = 10;
// $2a$ / $2b$ / $2y$ prefixes are bcrypt hashes; anything else is a legacy
// plaintext password written before hashing was introduced.
const isBcryptHash = (value) => typeof value === "string" && /^\$2[aby]\$\d{2}\$/.test(value);

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

// Issues a short-lived access cookie plus a longer-lived single-use refresh
// cookie. Refresh tokens are stored hashed: a leaked DB row is not a usable
// token.
async function issueSession(res, userId) {
  const access = jwt.sign({ user: { id: userId } }, jwtToken, { expiresIn: accessExpiresSec });
  const refresh = crypto.randomBytes(32).toString("hex");

  await RefreshToken.deleteMany({ expiresAt: { $lt: new Date() } });
  await RefreshToken.create({
    userId,
    tokenHash: sha256(refresh),
    expiresAt: new Date(Date.now() + refreshExpiresDays * 24 * 60 * 60 * 1000),
  });

  res.cookie("auth_token", access, { ...cookieOptions, maxAge: accessExpiresSec * 1000 });
  res.cookie("refresh_token", refresh, {
    ...cookieOptions,
    maxAge: refreshExpiresDays * 24 * 60 * 60 * 1000,
    path: "/refresh",
  });
}

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
  // Cookie is the primary channel; the header stays for non-browser clients.
  const token = req.cookies?.auth_token || req.header("auth-token");

  if (!token) {
    return res.status(401).json({ success: false, errors: "Please authenticate using valid token!" });
  }

  try {
    const data = jwt.verify(token, jwtToken);
    req.user = data.user;
    next();
  } catch (error) {
    // "session_expired" lets the SPA hit /refresh instead of dumping the user
    // back on the login screen.
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ success: false, errors: "Session expired", code: "session_expired" });
    }
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
// fileFilter only sees the mimetype the client declares in the part header; the
// bytes can be anything. A part claiming image/png that contains HTML would be
// stored as .png and served from /images. So the extension comes from the
// sniffed signature, never from mimetype or the client-supplied originalname
// (an attacker can name a file "payload.html.png").
const ALLOWED_IMAGE_TYPES = {
  "image/jpeg": ".jpg",
  "image/png": ".png",
  "image/webp": ".webp",
  "image/gif": ".gif",
};

const PNG_SIGNATURE = Buffer.from("89504e470d0a1a0a", "hex");

const IMAGE_SIGNATURES = [
  {
    type: "image/jpeg",
    ext: ".jpg",
    match: (b) => b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff,
  },
  {
    type: "image/png",
    ext: ".png",
    match: (b) => b.length >= 8 && b.subarray(0, 8).equals(PNG_SIGNATURE),
  },
  {
    type: "image/gif",
    ext: ".gif",
    match: (b) => b.length >= 6 && ["GIF87a", "GIF89a"].includes(b.subarray(0, 6).toString("latin1")),
  },
  {
    type: "image/webp",
    ext: ".webp",
    match: (b) =>
      b.length >= 12 &&
      b.subarray(0, 4).toString("latin1") === "RIFF" &&
      b.subarray(8, 12).toString("latin1") === "WEBP",
  },
];

// Longest signature: WebP needs RIFF + size + WEBP, so 12 bytes are enough.
const SNIFF_BYTES = 12;
const sniffImage = (buffer) => IMAGE_SIGNATURES.find((s) => s.match(buffer)) || null;

// Custom engine instead of diskStorage: diskStorage names and opens the file
// before any byte arrives, so it cannot look at the content. Here the first
// bytes are verified before anything is written, so a rejected part never
// reaches the disk.
// Write streams still open for a file, so _removeFile can wait for the
// descriptor to close before unlinking (Windows refuses to unlink open files).
const openStreams = new WeakMap();

const storage = {
  _handleFile(req, file, cb) {
    let settled = false;
    let flushed = false;
    const finish = (error, info) => {
      if (settled) return;
      settled = true;
      cb(error, info);
    };

    const reject = () => {
      const error = new Error("File content does not match an allowed image signature");
      error.status = 400;
      file.stream.destroy();
      return finish(error);
    };

    const head = [];
    let headSize = 0;

    const write = (signature) => {
      if (flushed) return;
      flushed = true;

      const filename = `${file.fieldname}_${Date.now()}${signature.ext}`;
      const filepath = path.join(uploadDir, filename);
      const out = fs.createWriteStream(filepath);
      const info = () => ({ destination: uploadDir, filename, path: filepath, size: out.bytesWritten });

      file.path = filepath;
      openStreams.set(file, out);
      out.on("close", () => {
        openStreams.delete(file);
        if (!settled) finish(null, info());
      });

      out.write(Buffer.concat(head));

      // A file smaller than the sniff window has already ended: nothing left to pipe.
      if (file.stream.readableEnded || file.stream.destroyed) {
        out.end();
        return;
      }

      // pipeline ends the destination and reports source errors (busboy destroys
      // the file stream when a limit is hit or the client aborts).
      pipeline(file.stream, out, (error) => {
        if (error) finish(error);
      });
    };

    const onHead = (chunk) => {
      head.push(chunk);
      headSize += chunk.length;
      if (headSize < SNIFF_BYTES) return;

      file.stream.removeListener("data", onHead);
      const signature = sniffImage(Buffer.concat(head));
      if (!signature) return reject();
      write(signature);
    };

    file.stream.on("data", onHead);
    file.stream.on("end", () => {
      // Only reached for files smaller than the sniff window; a flushed file
      // must not be written a second time.
      if (flushed || settled) return;
      const signature = sniffImage(Buffer.concat(head));
      if (!signature) return reject();
      write(signature);
    });
    file.stream.on("error", finish);
  },

  _removeFile(req, file, cb) {
    const filepath = file.path;
    delete file.path;
    if (!filepath) return cb();

    const out = openStreams.get(file);
    if (!out) return fs.unlink(filepath, (error) => cb(error));

    // Abort can land while the write stream is still finishing; unlinking an
    // open descriptor fails on Windows, so wait for close.
    out.once("close", () => {
      openStreams.delete(file);
      fs.unlink(filepath, (error) => cb(error));
    });
  },
};

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
app.use("/images", express.static(seedDir));

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

// Session probe: the SPA decides whether it is logged in without ever touching
// the token itself.
app.get(
  "/me",
  fetchUser,
  asyncHandler(async (req, res) => {
    const user = await Users.findById(req.user.id).select("name email role");
    if (!user) {
      return res.status(404).json({ success: false, errors: "User not found" });
    }
    res.json({ success: true, name: user.name, email: user.email, role: user.role });
  })
);

app.post(
  "/refresh",
  authLimiter,
  asyncHandler(async (req, res) => {
    const refresh = req.cookies?.refresh_token;
    if (!refresh) {
      return res.status(401).json({ success: false, errors: "No refresh token" });
    }

    const stored = await RefreshToken.findOne({ tokenHash: sha256(refresh) });
    if (!stored || stored.expiresAt < new Date()) {
      return res.status(401).json({ success: false, errors: "Refresh token is not valid" });
    }

    // Rotation: the presented refresh token is single-use.
    await RefreshToken.deleteOne({ _id: stored._id });
    await issueSession(res, stored.userId);
    res.json({ success: true });
  })
);

app.post(
  "/logout",
  asyncHandler(async (req, res) => {
    const refresh = req.cookies?.refresh_token;
    if (refresh) {
      await RefreshToken.deleteOne({ tokenHash: sha256(refresh) });
    }
    res.clearCookie("auth_token", { path: "/" });
    res.clearCookie("refresh_token", { path: "/refresh" });
    res.json({ success: true });
  })
);

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

// Optional pagination: ?page=2&limit=50. Without query params the whole list is
// returned, so existing SPA code keeps working unchanged.
app.get(
  "/allProducts",
  asyncHandler(async (req, res) => {
    const page = Math.max(1, Number(req.query.page) || 1);
    const requestedLimit = Number(req.query.limit) || 0;

    if (!requestedLimit) {
      return res.json(await Product.find({}));
    }

    const limit = Math.min(100, Math.max(1, requestedLimit));
    const total = await Product.countDocuments();
    const products = await Product.find({}).sort({ id: 1 }).skip((page - 1) * limit).limit(limit);

    res.set("X-Total-Count", String(total));
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

    await issueSession(res, user.id);
    res.status(200).json({ success: true, name: user.name });
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

    await issueSession(res, user.id);
    res.json({ success: true, name: user.name });
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

module.exports = { app, server };

server.on("error", (error) => {
  console.error("Server error:", error.message);
  process.exit(1);
});
