/**
 * Admin kullanıcısı oluşturur veya mevcut kullanıcıyı admin yapar.
 *
 * Kullanım:
 *   npm run create-admin -- admin@example.com gizliSifre
 *
 * Not: Kullanıcı zaten varsa rolü admin yapılır ve şifresi verilen şifreyle
 * güncellenir (hash'lenerek).
 */
require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const { Users, createEmptyCart } = require("../models");

const BCRYPT_ROUNDS = 10;

const [email, password] = process.argv.slice(2);

if (!email || !password) {
  console.error("Kullanım: npm run create-admin -- <email> <password>");
  process.exit(1);
}

if (password.length < 6) {
  console.error("Şifre en az 6 karakter olmalı.");
  process.exit(1);
}

if (!process.env.MONGO_CONNECT) {
  console.error("Missing MONGO_CONNECT in .env (see .env.example)");
  process.exit(1);
}

const upsertAdmin = async (existingUser) => {
  const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);

  if (existingUser) {
    existingUser.role = "admin";
    existingUser.password = hashedPassword;
    if (!existingUser.cartData) {
      existingUser.cartData = createEmptyCart();
    }
    await existingUser.save();
    console.log(`Admin yapıldı (şifre güncellendi): ${email}`);
    return;
  }

  await Users.create({
    name: "Admin",
    email,
    password: hashedPassword,
    role: "admin",
    cartData: createEmptyCart(),
  });
  console.log(`Admin oluşturuldu: ${email}`);
};

mongoose
  .connect(process.env.MONGO_CONNECT)
  .then(async () => {
    const existingUser = await Users.findOne({ email });
    await upsertAdmin(existingUser);
  })
  .catch((error) => {
    console.error("Hata:", error.message);
    process.exitCode = 1;
  })
  .finally(() => mongoose.disconnect());
