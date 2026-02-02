require("dotenv").config();

const path = require("path");
const fs = require("fs");
const express = require("express");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const pool = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;

// FILE FALLBACK SETUP
const INVITES_FILE = path.join(__dirname, "data", "invites.ndjson");

// SECURITY SETUP
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || "changeme").trim();
console.log(`Admin Password Loaded. Length: ${ADMIN_PASSWORD.length} chars`);

const SITE_URL = (process.env.SITE_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const PDF_TOKEN_MINUTES = Number(process.env.PDF_TOKEN_MINUTES || 60);

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.set("trust proxy", 1);

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);

app.use((req, res, next) => {
  req.cookies = {};
  const raw = req.headers.cookie;
  if (raw) {
    raw.split(";").forEach((c) => {
      const [k, ...rest] = c.split("=");
      req.cookies[k.trim()] = decodeURIComponent(rest.join("=") || "");
    });
  }
  next();
});

/* --- HELPERS --- */

function site() {
  return { name: "Atmakosh LLM", tagline: "The Soul-Repository AI" };
}

function hash(v) {
  return crypto.createHash("sha256").update(v).digest("hex");
}

function isAdmin(req) {
  return req.cookies.admin === hash(ADMIN_PASSWORD);
}

// Helper: Read invites from local file (used when DB is down)
function getFileInvites() {
  if (!fs.existsSync(INVITES_FILE)) return [];
  try {
    const content = fs.readFileSync(INVITES_FILE, "utf-8");
    return content
      .trim()
      .split("\n")
      .map((line, idx) => {
        try {
          const r = JSON.parse(line);
          // Add a fake ID for the view logic
          r.id = "file_" + idx; 
          r.is_fallback = true;
          return r;
        } catch (e) { return null; }
      })
      .filter(Boolean);
  } catch (e) {
    console.error("Error reading invite file:", e.message);
    return [];
  }
}

function getIP(req) {
  const xf = String(req.headers["x-forwarded-for"] || "");
  const ip = xf ? xf.split(",")[0].trim() : String(req.socket.remoteAddress || "");
  return ip.slice(0, 80);
}

function getUA(req) {
  return String(req.headers["user-agent"] || "").slice(0, 255);
}

async function audit(req, event, meta = {}) {
  try {
    await pool.execute(
      "INSERT INTO audit_log (event, actor, ip, user_agent, meta) VALUES (?, ?, ?, ?, ?)",
      [event, "system", getIP(req), getUA(req), JSON.stringify(meta)]
    );
  } catch (e) {
    // Ignore audit errors
  }
}

function mailer() {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const secure = String(process.env.SMTP_SECURE || "false").toLowerCase() === "true";

  if (!host || !user || !pass) return null;

  return nodemailer.createTransport({
    host, port, secure, auth: { user, pass },
  });
}

async function getEmailTemplate(name) {
  try {
    const [rows] = await pool.execute("SELECT * FROM email_templates WHERE name=? LIMIT 1", [name]);
    return rows[0] || null;
  } catch (e) { return null; }
}

async function sendApprovalEmail(toEmail, opts = {}) {
  const transport = mailer();
  if (!transport) return;
  
  // Simplified email logic for robustness
  const from = process.env.SMTP_FROM || process.env.SMTP_USER;
  const subject = "Your Atmakosh LLM preview access is approved";
  const accessUrl = `${SITE_URL}/whitepapers/access`;
  const text = `Your access is approved. Visit: ${accessUrl}`;
  
  try {
    await transport.sendMail({ from, to: toEmail, subject, text });
  } catch (e) { console.error("Email failed:", e.message); }
}

async function sendInviteReceivedEmail(name, toEmail) {
  const transport = mailer();
  if (!transport) return;

  const from = process.env.SMTP_FROM || process.env.SMTP_USER;
  const subject = "Atmakosh Invite Request Received";
  const text = `Hello ${name}, we received your request.`;

  try {
    await transport.sendMail({ from, to: toEmail, subject, text });
  } catch (e) { console.error("Receipt email failed:", e.message); }
}

const PAPERS = [
  { slug: "plural-intelligence", title: "Plural Intelligence", file: "plural-intelligence.pdf" },
  { slug: "governance-first-ai", title: "Governance-First AI", file: "governance-first-ai.pdf" },
  { slug: "decision-systems-for-boards", title: "Decision Systems for Boards", file: "decision-systems-for-boards.pdf" },
  { slug: "ethics-without-ideology", title: "Ethics Without Ideology", file: "ethics-without-ideology.pdf" },
];

function scoreInvite(intent = "") {
  let score = 0;
  const text = String(intent || "").toLowerCase();
  if (text.includes("governance")) score += 2;
  if (text.includes("ethics")) score += 2;
  return score;
}

// Rate Limits
const generalLimiter = rateLimit({ windowMs: 60*1000, max: 120 });
const accessLimiter = rateLimit({ windowMs: 10*60*1000, max: 20 });
const downloadLimiter = rateLimit({ windowMs: 10*60*1000, max: 30 });
const statusLimiter = rateLimit({ windowMs: 15*60*1000, max: 10 });

app.use(generalLimiter);

app.use((req, res, next) => {
  res.locals.SITE = site();
  res.locals.SITE_URL = SITE_URL;
  res.locals.path = req.path;
  res.locals.META = null;
  next();
});

/* --- ROUTES --- */

app.get("/", (req, res) => res.render("pages/home"));

app.get("/invite", (req, res) => res.render("pages/invite", { query: req.query }));

app.get("/whitepapers", (req, res) => res.render("pages/whitepapers", { papers: PAPERS }));

/* ROBUST INVITE SUBMISSION */
app.post("/api/invite", async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const intent = String(req.body.intent || "").trim();
  const score = scoreInvite(intent);

  if (!email) return res.status(400).send("Email required");

  let savedToDb = false;

  // 1. Try Database
  try {
    await pool.execute(
      "INSERT INTO invites (name, email, intent, status, score) VALUES (?, ?, ?, 'pending', ?)",
      [name, email, intent, score]
    );
    savedToDb = true;
  } catch (e) {
    if (e.code === "ER_DUP_ENTRY") return res.redirect("/invite?duplicate=1");
    console.error("DB Write Failed:", e.message);
  }

  // 2. Fallback to File
  if (!savedToDb) {
    try {
      const fileRecs = getFileInvites();
      if (fileRecs.find(r => r.email === email)) return res.redirect("/invite?duplicate=1");

      const record = { name, email, intent, score, status: 'pending', created_at: new Date() };
      fs.appendFileSync(INVITES_FILE, JSON.stringify(record) + "\n");
    } catch (e) {
      console.error("File Write Failed:", e.message);
      return res.status(500).send("System busy, please try again.");
    }
  }

  // Side effects
  try { await sendInviteReceivedEmail(name, email); } catch {}
  
  return res.redirect("/invite?submitted=1");
});

/* ADMIN ROUTES */

app.get("/admin", (req, res) => res.render("pages/admin-login", { error: null }));

app.post("/admin", async (req, res) => {
  const input = String(req.body.password || "").trim();
  if (input === ADMIN_PASSWORD) {
    res.setHeader("Set-Cookie", `admin=${hash(ADMIN_PASSWORD)}; HttpOnly; Path=/; SameSite=Lax`);
    return res.redirect("/admin/invites");
  }
  res.render("pages/admin-login", { error: "Invalid password" });
});

app.get("/admin/invites", async (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");

  let dbRows = [];
  
  // 1. Try fetching from DB
  try {
    const [rows] = await pool.execute("SELECT * FROM invites ORDER BY created_at DESC");
    dbRows = rows;
  } catch (e) {
    console.error("Admin DB Read Failed:", e.message);
    // Do NOT crash. Just continue to load file records.
  }

  // 2. Load File Records
  const fileRows = getFileInvites().reverse(); // Show newest first

  // 3. Merge lists
  // (In a real app you might want to deduplicate by email, but concat is safer here)
  const allRows = [...fileRows, ...dbRows];

  res.render("pages/admin-invites", { rows: allRows });
});

/* Admin Analytics - Robust Version */
app.get("/admin/analytics", async (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");

  // Fetch all data (DB + File) and calculate stats manually in JS
  let allRows = getFileInvites();
  try {
    const [dbRows] = await pool.execute("SELECT status FROM invites");
    allRows = allRows.concat(dbRows);
  } catch (e) {
    console.error("Analytics DB Fail:", e.message);
  }

  const counts = {
    total: allRows.length,
    pending: allRows.filter(r => r.status === 'pending').length,
    approved: allRows.filter(r => r.status === 'approved').length,
    rejected: allRows.filter(r => r.status === 'rejected').length
  };

  res.render("pages/admin-analytics", { counts });
});

/* Invite Actions (Only work if DB is up) */
app.post("/admin/invite/:id/approve", async (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");
  const id = req.params.id;
  
  // If ID starts with "file_", we can't update DB. Just ignore or log.
  if (id.toString().startsWith("file_")) {
    return res.redirect("/admin/invites"); // Cannot approve file-only invites yet
  }

  try {
    const [rows] = await pool.execute("SELECT email, name FROM invites WHERE id=?", [id]);
    if (rows.length) {
      await pool.execute("UPDATE invites SET status='approved' WHERE id=?", [id]);
      await sendApprovalEmail(rows[0].email, { name: rows[0].name });
    }
  } catch(e) {}
  res.redirect("/admin/invites");
});

app.post("/admin/invite/:id/reject", async (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");
  try {
    await pool.execute("UPDATE invites SET status='rejected' WHERE id=?", [req.params.id]);
  } catch(e) {}
  res.redirect("/admin/invites");
});

// Admin Logout
app.get("/admin/logout", (req, res) => {
  res.setHeader("Set-Cookie", "admin=; HttpOnly; Path=/; Max-Age=0");
  res.redirect("/");
});

/* PUBLIC PAGES */
app.get("/why-atmakosh", (req, res) => res.render("pages/why-atmakosh"));
app.get("/leadership", (req, res) => res.render("pages/leadership"));
app.get("/terms", (req, res) => res.render("pages/terms"));

/* 404 */
app.use((req, res) => {
  res.status(404).render("pages/404");
});

app.listen(PORT, () => console.log(`Atmakosh site running on ${PORT}`));
