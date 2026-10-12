// Backend security + session tests.
// Run with: npm test
//
// Uses an in-memory MongoDB so the suite is self-contained and never touches a
// real database.

const path = require("path");
const assert = require("node:assert");
const { test } = require("node:test");
const { MongoMemoryServer } = require("mongodb-memory-server");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { Users, Product } = require("../models");

const PORT = 4102;
const BASE = `http://localhost:${PORT}`;
const JWT_SECRET = "test-secret-key";

let mongo;
let started = false;

async function startServer() {
  if (started) return;
  mongo = await MongoMemoryServer.create();

  // Set before requiring index.js: dotenv does not override existing env vars.
  process.env.MONGO_CONNECT = mongo.getUri();
  process.env.JWT_TOKEN = JWT_SECRET;
  process.env.PORT = String(PORT);
  process.env.HOST = "http://localhost";
  process.env.CORS_ORIGINS = "http://localhost:5173";

  require("../index.js");

  await new Promise((resolve) => setTimeout(resolve, 1500));

  await Users.create({
    name: "Admin",
    email: "admin@test.com",
    password: bcrypt.hashSync("admin123", 10),
    role: "admin",
    cartData: {},
  });
  await Users.create({
    name: "Ali",
    email: "ali@test.com",
    password: bcrypt.hashSync("user123", 10),
    role: "user",
    cartData: {},
  });
  await Users.create({
    name: "Legacy",
    email: "legacy@test.com",
    password: "plaintext123", // pre-bcrypt record, upgraded on first login
    role: "user",
    cartData: {},
  });

  for (let i = 1; i <= 12; i++) {
    await Product.create({
      id: i,
      name: `Product ${i}`,
      image: "http://localhost:4000/images/demo.png",
      category: i % 2 === 0 ? "women" : "men",
      new_price: 10 * i,
      old_price: 20 * i,
    });
  }

  started = true;
}

function cookiesOf(response) {
  const jar = {};
  for (const raw of response.headers.getSetCookie ? response.headers.getSetCookie() : []) {
    const [pair] = raw.split(";");
    const [name, value] = pair.split("=");
    jar[name] = value;
  }
  return jar;
}

function cookieHeader(jar) {
  return Object.entries(jar)
    .map(([name, value]) => `${name}=${value}`)
    .join("; ");
}

async function request(pathname, { method = "GET", body, jar, headers = {} } = {}) {
  return fetch(BASE + pathname, {
    method,
    headers: {
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(jar ? { cookie: cookieHeader(jar) } : {}),
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
  });
}

async function login(email, password) {
  const response = await request("/login", { method: "POST", body: { email, password } });
  return { response, jar: cookiesOf(response), body: await response.json() };
}

test("setup: server and seed data are ready", async () => {
  await startServer();
  const response = await fetch(BASE + "/");
  assert.strictEqual(response.status, 200);
});

test("login sets an httpOnly SameSite cookie and never returns the token", async () => {
  const { response, jar, body } = await login("admin@test.com", "admin123");

  assert.strictEqual(response.status, 200);
  assert.ok(!("token" in body), "token must not be in the response body");
  assert.ok("auth_token" in jar, "auth_token cookie present");
  assert.ok("refresh_token" in jar, "refresh_token cookie present");

  const raw = response.headers.getSetCookie().join("\n");
  assert.match(raw, /httponly/i);
  assert.match(raw, /samesite=strict/i);
});

test("wrong password is rejected with a non-enumerating message", async () => {
  const response = await request("/login", { method: "POST", body: { email: "admin@test.com", password: "nope" } });
  const body = await response.json();
  assert.strictEqual(response.status, 401);
  assert.strictEqual(body.errors, "Invalid email or password.");

  const unknown = await request("/login", { method: "POST", body: { email: "ghost@test.com", password: "nope" } });
  assert.strictEqual(unknown.status, 401);
  assert.strictEqual((await unknown.json()).errors, "Invalid email or password.");
});

test("legacy plaintext password is upgraded to bcrypt on first login", async () => {
  const { jar } = await login("legacy@test.com", "plaintext123");
  const me = await request("/me", { jar });
  assert.strictEqual(me.status, 200);

  const user = await Users.findOne({ email: "legacy@test.com" });
  assert.match(user.password, /^\$2[aby]\$\d{2}\$/);
  void jar;
});

test("protected routes need the cookie; anonymous requests get 401", async () => {
  const { jar } = await login("admin@test.com", "admin123");

  const withCookie = await request("/me", { jar });
  assert.strictEqual(withCookie.status, 200);

  const withoutCookie = await request("/me");
  assert.strictEqual(withoutCookie.status, 401);
});

test("a non-admin cannot reach admin endpoints", async () => {
  const { jar } = await login("ali@test.com", "user123");
  const response = await request("/addProduct", {
    method: "POST",
    jar,
    body: { name: "x", image: "y", category: "women", new_price: 1, old_price: 2 },
  });
  assert.strictEqual(response.status, 403);
});

test("an expired access token is answered with session_expired", async () => {
  // Craft a token with the same secret but a past expiry instead of waiting 15 min.
  const user = await Users.findOne({ email: "admin@test.com" });
  const expired = jwt.sign({ user: { id: user.id } }, JWT_SECRET, { expiresIn: -60 });

  const response = await request("/me", { jar: { auth_token: expired } });
  const body = await response.json();

  assert.strictEqual(response.status, 401);
  assert.strictEqual(body.code, "session_expired");
});

test("/refresh rotates the session: old refresh token stops working", async () => {
  const { jar } = await login("admin@test.com", "admin123");

  const refreshed = await request("/refresh", { method: "POST", jar });
  assert.strictEqual(refreshed.status, 200);
  const newJar = cookiesOf(refreshed);
  assert.ok(newJar.auth_token && newJar.refresh_token, "new cookies issued");
  assert.notStrictEqual(newJar.refresh_token, jar.refresh_token, "refresh token is rotated");

  const reused = await request("/refresh", { method: "POST", jar });
  assert.strictEqual(reused.status, 401, "the presented refresh token is single-use");

  const meWithNewCookie = await request("/me", { jar: newJar });
  assert.strictEqual(meWithNewCookie.status, 200);
});

test("logout clears both cookies and revokes the refresh token", async () => {
  const { jar } = await login("admin@test.com", "admin123");
  const logout = await request("/logout", { method: "POST", jar });
  assert.strictEqual(logout.status, 200);

  const cleared = cookiesOf(logout);
  assert.ok(!cleared.auth_token, "auth_token is cleared");
  assert.ok(!cleared.refresh_token, "refresh_token is cleared");

  const afterLogout = await request("/refresh", { method: "POST", jar });
  assert.strictEqual(afterLogout.status, 401);
});

test("allProducts returns everything by default and paginates when asked", async () => {
  const all = await request("/allProducts");
  const products = await all.json();
  assert.strictEqual(products.length, 12, "default: full list, backwards compatible");

  const page = await request("/allProducts?page=2&limit=5");
  const items = await page.json();
  assert.strictEqual(items.length, 5);
  assert.strictEqual(items[0].id, 6, "page 2 starts at id 6");
  assert.strictEqual(page.headers.get("x-total-count"), "12");

});

test("uploads must be real images", async () => {
  const { jar } = await login("admin@test.com", "admin123");

  const form = new FormData();
  form.append("product", new Blob(["<script>alert(1)</script>"], { type: "text/html" }), "evil.html");

  const response = await fetch(BASE + "/upload", { method: "POST", body: form, headers: { cookie: cookieHeader(jar) } });
  assert.strictEqual(response.status, 400);
});

test("helmet security headers are present", async () => {
  const response = await fetch(BASE + "/");
  assert.ok(response.headers.get("content-security-policy"), "CSP header");
  assert.strictEqual(response.headers.get("x-content-type-options"), "nosniff");
  assert.strictEqual(response.headers.get("x-frame-options"), "SAMEORIGIN");
});

test("unknown origins are refused by CORS", async () => {
  const response = await fetch(BASE + "/allProducts", { headers: { origin: "http://evil.example" } });
  assert.strictEqual(response.status, 403);
});

test("login is rate limited", async () => {
  let lastStatus = 0;
  for (let i = 0; i < 25; i++) {
    const response = await request("/login", { method: "POST", body: { email: "admin@test.com", password: "wrong" } });
    lastStatus = response.status;
  }
  assert.strictEqual(lastStatus, 429, "the 21st attempt is blocked");
});

test("shutdown: server and database close cleanly", async () => {
  const mongoose = require("mongoose");
  const { server } = require("../index.js");
  await new Promise((resolve) => server.close(resolve));
  await mongoose.disconnect();
  if (mongo) await mongo.stop();
});
