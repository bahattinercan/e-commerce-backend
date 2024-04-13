const express = require("express");
const app = express();
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const cors = require("cors");
require("dotenv").config();

app.use(express.json());
app.use(cors());

const port = process.env.PORT || 4000;
const jwtToken = process.env.JWT_TOKEN;

// Database Connection With Mongo DB
mongoose.connect("mongodb+srv://bahattin:99Bvq1Vv2V2so4CF@cluster0.cpbxvk9.mongodb.net/e-commerce");

// api creation

app.get("/", (req, res) => {
  res.send("Express App is Running!!!");
});

// image storage engine

const storage = multer.diskStorage({
  destination: "./upload/images",
  filename: (req, file, cb) => {
    return cb(null, `${file.fieldname}_${Date.now()}${path.extname(file.originalname)}`);
  },
});

const upload = multer({ storage: storage });

// creating upload endpoint for images
app.use("/images", express.static("upload/images"));

app.post("/upload", upload.single("product"), (req, res) => {
  res.json({
    success: 1,
    image_url: `http://localhost:${port}/images/${req.file.filename}`,
  });
});

const fetchUser = async (req, res, next) => {
  const token = req.header("auth-token");
  if (!token) {
    res.status(401), send({ errors: "Please authenticate using valid token!" });
  } else {
    try {
      const data = jwt.verify(token, jwtToken);
      req.user = data.user;
      next();
    } catch (error) {
      console.log("error : " + error);
      res.status(401), send({ errors: "Token is not valid!" });
    }
  }
};

//#region  Schemas

const Product = mongoose.model("Product", {
  id: { type: Number, required: true },
  name: { type: String, required: true },
  image: { type: String, required: true },
  category: { type: String, required: true },
  new_price: { type: Number, required: true },
  old_price: { type: Number, required: true },
  date: { type: Date, default: Date.now },
  available: { type: Boolean, default: true },
});

const Users = mongoose.model("Users", {
  name: { type: String },
  email: { type: String, unique: true },
  password: { type: String },
  cartData: { type: Object },
  date: { type: Date, default: Date.now },
});

//#endregion

//#region Product Functions

app.post("/addProduct", async (req, res) => {
  const { name, image, category, new_price, old_price } = req.body;
  let products = await Product.find({});
  let lastId;
  if (products.length > 0) {
    let lastProduct = products[products.length - 1];
    lastId = lastProduct.id + 1;
  } else {
    lastId = 1;
  }

  const product = new Product({
    id: lastId,
    name: name,
    image: image,
    category: category,
    new_price: new_price,
    old_price: old_price,
  });

  console.log(product);
  await product.save();
  console.log("Saved");
  res.json({ success: true, name: req.body.name });
});

// Creating api for deleting products
app.post("/removeProduct", async (req, res) => {
  const { id, name } = req.body;
  await Product.findOneAndDelete({ id: id });
  console.log("Removed");
  res.json({ success: true, name: name });
});

// Creating api for getting all products
app.get("/allProducts", async (req, res) => {
  let products = await Product.find({});
  console.log("Get All Products");
  res.json(products);
});

app.get("/newCollections", async (req, res) => {
  let products = await Product.find({});
  let newCollection = products.slice(1).slice(-8);
  console.log("New Collection Fetched");
  res.status(200).json(newCollection);
});

app.get("/popularInWomen", async (req, res) => {
  let products = await Product.find({ category: "women" });
  let newCollection = products.slice(0, 4);
  console.log("New Collection Fetched");
  res.status(200).json(newCollection);
});

app.post("/addToCart", fetchUser, async (req, res) => {
  const { id } = req.user;
  const { itemId } = req.body;

  let userData = await Users.findOne({ _id: id });
  userData.cartData[itemId] += 1;
  await Users.findOneAndUpdate({ _id: id }, { cartData: userData.cartData });
  console.log("Add to Cart");
  res.status(200).send("Added");
});

app.post("/removeFromCart", fetchUser, async (req, res) => {
  const { id } = req.user;
  const { itemId } = req.body;

  let userData = await Users.findOne({ _id: id });
  if (userData.cartData[itemId] > 0) {
    userData.cartData[itemId] -= 1;
  }
  await Users.findOneAndUpdate({ _id: id }, { cartData: userData.cartData });
  console.log("Removed from Cart");
  res.status(200).send("Removed");
});

app.post("/getCart", fetchUser, async (req, res) => {
  const { id } = req.user;
  let userData = await Users.findOne({ _id: id });

  res.status(200).json(userData.cartData);

  console.log("Get Cart");
});

//#endregion

//#region User Functions
app.post("/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    let check = await Users.findOne({ email: email });
    if (check) {
      return res.status(400).json({ success: false, errors: "This email is already in use!" });
    }
    let cart = {};
    for (let i = 0; i < 300; i++) {
      cart[i] = 0;
    }
    const user = new Users({ name: username, email: email, password: password, cartData: cart });

    await user.save();

    const data = {
      user: { id: user.id },
    };

    const token = jwt.sign(data, jwtToken);
    res.status(200).json({ success: true, token });
  } catch (error) {
    console.log("ERROR:" + error);
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  let user = await Users.findOne({ email: email });
  if (user) {
    if (user.password === password) {
      const data = {
        user: { id: user.id },
      };
      const token = jwt.sign(data, jwtToken);
      res.json({ success: true, token });
    } else {
      res.status(404).json({ success: false, errors: "Wrong password!" });
    }
  } else {
    res.status(404).json({ success: false, errors: "Email not found!" });
  }
});
//#endregion

app.listen(port, (error) => {
  if (!error) {
    console.log("Server Running on Port " + port);
  } else {
    console.log("Error : " + error);
  }
});
