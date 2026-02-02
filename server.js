require("dotenv").config();

const path = require("path");
const fs = require("fs");
const express = require("express");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;

/* --- DATA PATHS --- */
const DATA_DIR = path.join(__dirname, "data");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const INVITES_FILE = path.join(DATA_DIR, "invites.ndjson");
const TOKENS_FILE = path.join(DATA_DIR, "tokens.ndjson");
const AUDIT_FILE = path.join(DATA_DIR, "audit.ndjson");
const TEMPLATES_FILE = path.join(DATA_DIR, "email_templates.json");
const SECRET_FILE = path.join(DATA_DIR, "admin_secret.txt");

/* --- CONFIG --- */
let loadedPassword = "changeme";
if (fs.existsSync(SECRET_FILE)) {
  try { loadedPassword = fs.readFileSync(SECRET_FILE, "utf-8").trim() || "changeme"; } catch {}
} else if (process.env.ADMIN_PASSWORD) {
  loadedPassword = String(process.env.ADMIN_PASSWORD).trim();
}
const ADMIN_PASSWORD = loadedPassword;

const SITE_URL = (process.env.SITE_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const PDF_TOKEN_MINUTES = Number(process.env.PDF_TOKEN_MINUTES || 60);

/* --- MIDDLEWARE --- */
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.set("trust proxy", 1);
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(helmet({ contentSecurityPolicy: false }));
app.use((req, res, next) => {
  req.cookies = {};
  const raw = req.headers.cookie;
  if (raw) raw.split(";").forEach(c => { const [k, v] = c.split("="); req.cookies[k.trim()] = decodeURIComponent(v || ""); });
  next();
});

/* --- DATA HELPERS --- */
function readNDJSON(filePath) {
  if (!fs.existsSync(filePath)) return [];
  try {
    return fs.readFileSync(filePath, "utf-8").trim().split("\n")
      .map(line => { try { return JSON.parse(line); } catch { return null; } })
      .filter(Boolean);
  } catch { return []; }
}
function appendNDJSON(filePath, record) {
  try { fs.appendFileSync(filePath, JSON.stringify(record) + "\n"); return true; } catch { return false; }
}
function updateNDJSON(filePath, records) {
  try { fs.writeFileSync(filePath, records.map(r => JSON.stringify(r)).join("\n") + "\n"); return true; } catch { return false; }
}
function readJSON(path) { try { return JSON.parse(fs.readFileSync(path, "utf-8")); } catch { return null; } }
function writeJSON(path, data) { try { fs.writeFileSync(path, JSON.stringify(data, null, 2)); return true; } catch { return false; } }

function generateId() { return Date.now().toString(36) + Math.random().toString(36).substr(2, 5); }

/* --- DATA HEALER (Fixes missing IDs) --- */
function healData() {
  const records = readNDJSON(INVITES_FILE);
  let changed = false;
  const fixed = records.map(r => {
    if (!r.id) { r.id = generateId(); changed = true; } // Assign ID if missing
    return r;
  });
  if (changed) {
    updateNDJSON(INVITES_FILE, fixed);
    console.log("System: Healed data - Fixed missing IDs.");
  }
}
healData(); // Run on startup

/* --- UTILS --- */
function hash(v) { return crypto.createHash("sha256").update(v).digest("hex"); }
function isAdmin(req) { return req.cookies.admin === hash(ADMIN_PASSWORD); }
function getIP(req) { return (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim().slice(0, 80); }
function scoreInvite(intent = "") {
  let s = 0; const t = (intent || "").toLowerCase();
  if (t.includes("governance")) s += 2;
  if (t.includes("ethics")) s += 2;
  if (t.length > 200) s += 1;
  return s;
}

/* --- ROUTES --- */
const generalLimiter = rateLimit({ windowMs: 60 * 1000, max: 120 });
app.use(generalLimiter);

app.use((req, res, next) => {
  res.locals.SITE = { name: "Atmakosh LLM", tagline: "The Soul-Repository AI" };
  res.locals.SITE_URL = SITE_URL;
  res.locals.path = req.path;
  res.locals.META = null;
  next();
});

// Public Pages
app.get("/", (req, res) => res.render("pages/home"));
app.get("/invite", (req, res) => res.render("pages/invite", { query: req.query }));
app.get("/whitepapers", (req, res) => res.render("pages/whitepapers", { papers: [] }));
app.get("/leadership", (req, res) => res.render("pages/leadership"));
app.get("/terms", (req, res) => res.render("pages/terms"));

// Invite API
app.post("/api/invite", (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  if (!email) return res.status(400).send("Email required");
  
  const records = readNDJSON(INVITES_FILE);
  if (records.find(r => r.email === email)) return res.redirect("/invite?duplicate=1");

  const newInvite = {
    id: generateId(),
    name: req.body.name,
    email,
    intent: req.body.intent,
    score: scoreInvite(req.body.intent),
    status: 'pending',
    created_at: new Date().toISOString()
  };
  appendNDJSON(INVITES_FILE, newInvite);
  res.redirect("/invite?submitted=1");
});

// Admin Auth
app.get("/admin", (req, res) => res.render("pages/admin-login", { error: null }));
app.post("/admin", (req, res) => {
  const input = String(req.body.password || "").trim();
  if (input === ADMIN_PASSWORD) {
    res.setHeader("Set-Cookie", `admin=${hash(ADMIN_PASSWORD)}; HttpOnly; Path=/; SameSite=Lax`);
    return res.redirect("/admin/invites");
  }
  res.render("pages/admin-login", { error: "Invalid password" });
});

app.get("/admin/logout", (req, res) => {
  res.setHeader("Set-Cookie", "admin=; HttpOnly; Path=/; Max-Age=0");
  res.redirect("/");
});

// Admin Dashboard
app.get("/admin/invites", (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");
  const records = readNDJSON(INVITES_FILE).reverse();
  res.render("pages/admin-invites", { rows: records });
});

// Approve
app.post("/admin/invite/:id/approve", (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");
  const records = readNDJSON(INVITES_FILE);
  const updated = records.map(r => {
    if (r.id === req.params.id) r.status = 'approved';
    return r;
  });
  updateNDJSON(INVITES_FILE, updated);
  res.redirect("/admin/invites");
});

// Reject
app.post("/admin/invite/:id/reject", (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");
  const records = readNDJSON(INVITES_FILE);
  const updated = records.map(r => {
    if (r.id === req.params.id) r.status = 'rejected';
    return r;
  });
  updateNDJSON(INVITES_FILE, updated);
  res.redirect("/admin/invites");
});

// Analytics
app.get("/admin/analytics", (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");
  const records = readNDJSON(INVITES_FILE);
  const counts = {
    total: records.length,
    pending: records.filter(r => r.status === 'pending').length,
    approved: records.filter(r => r.status === 'approved').length,
    rejected: records.filter(r => r.status === 'rejected').length
  };
  res.render("pages/admin-analytics", { counts });
});

// 404
app.use((req, res) => res.status(404).render("pages/404"));

app.listen(PORT, () => console.log(`Atmakosh site running on ${PORT}`));
