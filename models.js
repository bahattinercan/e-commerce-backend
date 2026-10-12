const mongoose = require("mongoose");

// Mongoose keeps registered models on the connection: reuse them so the file can
// be required from several entry points (index.js, scripts) without
// OverwriteModelError.

const Product =
  mongoose.models.Product ||
  mongoose.model("Product", {
    id: { type: Number, required: true },
    name: { type: String, required: true },
    image: { type: String, required: true },
    category: { type: String, required: true },
    new_price: { type: Number, required: true },
    old_price: { type: Number, required: true },
    date: { type: Date, default: Date.now },
    available: { type: Boolean, default: true },
  });

const Users =
  mongoose.models.Users ||
  mongoose.model("Users", {
    name: { type: String },
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    role: { type: String, enum: ["user", "admin"], default: "user" },
    cartData: { type: Object },
    date: { type: Date, default: Date.now },
  });

const CART_SIZE = 301; // index 0..300, matches the frontend default cart

const createEmptyCart = () => {
  const cart = {};
  for (let i = 0; i < CART_SIZE; i++) {
    cart[i] = 0;
  }
  return cart;
};

module.exports = { Product, Users, createEmptyCart, CART_SIZE };
