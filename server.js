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

/* --- CONSTANTS --- */
const PAPERS = [
  { slug: "plural-intelligence", title: "Plural Intelligence", file: "plural-intelligence.pdf" },
  { slug: "governance-first-ai", title: "Governance-First AI", file: "governance-first-ai.pdf" },
  { slug: "decision-systems-for-boards", title: "Decision Systems for Boards", file: "decision-systems-for-boards.pdf" },
  { slug: "ethics-without-ideology", title: "Ethics Without Ideology", file: "ethics-without-ideology.pdf" }
];

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
  if (raw) raw.split(";").forEach(c => { const [k, ...v] = c.split("="); req.cookies[k.trim()] = decodeURIComponent(v.join("=") || ""); });
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
    if (!r.id) { r.id = generateId(); changed = true; } 
    return r;
  });
  if (changed) {
    updateNDJSON(INVITES_FILE, fixed);
    console.log("System: Healed data - Fixed missing IDs.");
  }
}
healData();

/* --- UTILS --- */
function hash(v) { return crypto.createHash("sha256").update(v).digest("hex"); }
function isAdmin(req) { return req.cookies.admin === hash(ADMIN_PASSWORD); }
function getIP(req) { return (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim().slice(0, 80); }
function getUA(req) { return String(req.headers["user-agent"] || "").slice(0, 255); }
function scoreInvite(intent = "") {
  let s = 0; const t = (intent || "").toLowerCase();
  if (t.includes("governance")) s += 2;
  if (t.includes("ethics")) s += 2;
  if (t.length > 200) s += 1;
  return s;
}

/* --- AUDIT & EMAIL --- */
function audit(req, event, meta={}) {
  appendNDJSON(AUDIT_FILE, { event, ip: getIP(req), ua: getUA(req), meta, created_at: new Date().toISOString() });
}

function mailer() {
  const host = process.env.SMTP_HOST;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  if (!host || !user || !pass) return null;
  return nodemailer.createTransport({ host, port: 587, auth: { user, pass } });
}

async function sendEmail(to, subject, text) {
  const t = mailer();
  if (!t) return;
  try { await t.sendMail({ from: process.env.SMTP_FROM, to, subject, text }); } catch {}
}

/* --- RATE LIMITS --- */
const generalLimiter = rateLimit({ windowMs: 60 * 1000, max: 120 });
const accessLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 20 });
const downloadLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 30 });
app.use(generalLimiter);

app.use((req, res, next) => {
  res.locals.SITE = { name: "Atmakosh LLM", tagline: "The Soul-Repository AI" };
  res.locals.SITE_URL = SITE_URL;
  res.locals.path = req.path;
  res.locals.META = null;
  next();
});

/* --- PUBLIC PAGES --- */
app.get("/", (req, res) => res.render("pages/home"));
app.get("/invite", (req, res) => res.render("pages/invite", { query: req.query }));
app.get("/leadership", (req, res) => res.render("pages/leadership"));
app.get("/terms", (req, res) => res.render("pages/terms"));
app.get("/why-atmakosh", (req, res) => res.render("pages/why-atmakosh"));
app.get("/whitepaper-vision", (req, res) => res.render("pages/whitepaper-vision"));

// Redirects
app.get("/team", (req, res) => res.redirect(301, "/leadership"));
app.get("/about", (req, res) => res.redirect(301, "/why-atmakosh"));

/* --- WHITEPAPERS (Restored) --- */
app.get("/whitepapers", (req, res) => {
  res.render("pages/whitepapers", { papers: PAPERS });
});

app.get("/whitepapers/access", accessLimiter, (req, res) => {
  res.locals.META = { robots: "noindex" };
  res.render("pages/whitepapers-access", { papers: null, error: null });
});

// Access Logic: Check email -> Generate Token
app.post("/whitepapers/access", accessLimiter, (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  
  // 1. Check if email exists AND is approved in invites.ndjson
  const invites = readNDJSON(INVITES_FILE);
  const userInvite = invites.reverse().find(r => r.email === email && r.status === 'approved');

  if (!userInvite) {
    return res.render("pages/whitepapers-access", { 
      papers: null, 
      error: "Access not approved. You must request an invite and be approved first." 
    });
  }

  // 2. Generate tokens
  const links = [];
  const expiresAt = new Date(Date.now() + PDF_TOKEN_MINUTES * 60 * 1000).toISOString();
  
  PAPERS.forEach(p => {
    const token = crypto.randomBytes(24).toString("hex");
    appendNDJSON(TOKENS_FILE, {
      email, paper: p.slug, token, expiresAt, ip: getIP(req), ua: getUA(req), used: false
    });
    links.push({ title: p.title, url: `${SITE_URL}/download/${token}` });
  });

  audit(req, "pdf_access_granted", { email });
  res.render("pages/whitepapers-access", { papers: links, error: null });
});

// Download Logic: Validate Token -> Serve File
app.get("/download/:token", downloadLimiter, (req, res) => {
  const token = req.params.token;
  const tokens = readNDJSON(TOKENS_FILE);
  const idx = tokens.findIndex(t => t.token === token);
  
  if (idx === -1) return res.status(403).send("Invalid or expired token");
  
  const t = tokens[idx];
  if (t.used) return res.status(403).send("This link has already been used.");
  if (new Date() > new Date(t.expiresAt)) return res.status(403).send("This link has expired.");
  if (t.ip && t.ip !== getIP(req)) return res.status(403).send("Security check failed (IP mismatch).");

  // Mark used
  t.used = true;
  t.usedAt = new Date().toISOString();
  tokens[idx] = t;
  updateNDJSON(TOKENS_FILE, tokens);

  const p = PAPERS.find(paper => paper.slug === t.paper);
  if (!p) return res.status(404).send("Paper definition not found.");

  const filePath = path.join(__dirname, "private", "pdfs", p.file);
  if (fs.existsSync(filePath)) {
    res.download(filePath);
  } else {
    res.status(404).send("PDF file missing on server.");
  }
});

/* --- INVITE API --- */
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
  
  // Notification (fire and forget)
  sendEmail(email, "Invitation Received", `Hello ${req.body.name}, we received your request.`);
  
  res.redirect("/invite?submitted=1");
});

app.get("/invite/status", statusLimiter, (req, res) => res.render("pages/invite-status", { result: null, error: null }));
app.post("/invite/status", statusLimiter, (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const records = readNDJSON(INVITES_FILE);
  const match = records.reverse().find(r => r.email === email);
  if (!match) return res.render("pages/invite-status", { result: null, error: "No request found." });
  res.render("pages/invite-status", { result: match, error: null });
});

/* --- ADMIN --- */
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

app.get("/admin/invites", (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");
  const records = readNDJSON(INVITES_FILE).reverse();
  res.render("pages/admin-invites", { rows: records });
});

app.post("/admin/invite/:id/approve", (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");
  const records = readNDJSON(INVITES_FILE);
  let targetEmail = null;
  const updated = records.map(r => {
    if (r.id === req.params.id) { r.status = 'approved'; targetEmail = r.email; }
    return r;
  });
  updateNDJSON(INVITES_FILE, updated);
  if (targetEmail) sendEmail(targetEmail, "Approved", "Your access is approved.");
  res.redirect("/admin/invites");
});

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

/* --- SYSTEM --- */
app.get("/sitemap.xml", (req, res) => {
  const urls = [`${SITE_URL}/`, `${SITE_URL}/invite`, `${SITE_URL}/whitepapers`, `${SITE_URL}/leadership`];
  const xml = `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls.map(u => `<url><loc>${u}</loc></url>`).join("")}</urlset>`;
  res.type("xml").send(xml);
});

app.get("/healthz", (req, res) => res.json({ ok: true }));

app.use((req, res) => res.status(404).render("pages/404"));

app.listen(PORT, () => console.log(`Atmakosh site running on ${PORT}`));
