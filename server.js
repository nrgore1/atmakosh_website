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

/* --- DATA STORAGE PATHS --- */
const DATA_DIR = path.join(__dirname, "data");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// File paths
const INVITES_FILE = path.join(DATA_DIR, "invites.ndjson");
const TOKENS_FILE = path.join(DATA_DIR, "tokens.ndjson");
const AUDIT_FILE = path.join(DATA_DIR, "audit.ndjson");
const TEMPLATES_FILE = path.join(DATA_DIR, "email_templates.json");
const PAPERS_CONFIG_FILE = path.join(DATA_DIR, "papers_config.json");
const SECRET_FILE = path.join(DATA_DIR, "admin_secret.txt");

/* --- CONFIG: ROBUST PASSWORD LOADING --- */
let loadedPassword = "changeme";

if (fs.existsSync(SECRET_FILE)) {
  try {
    const filePass = fs.readFileSync(SECRET_FILE, "utf-8").trim();
    if (filePass.length > 0) {
      loadedPassword = filePass;
      console.log("Configuration: Loaded password from data/admin_secret.txt");
    }
  } catch (e) {
    console.error("Warning: Could not read admin_secret.txt", e.message);
  }
} else if (process.env.ADMIN_PASSWORD) {
  loadedPassword = String(process.env.ADMIN_PASSWORD).trim();
  console.log("Configuration: Loaded password from Environment Variable");
}

const ADMIN_PASSWORD = loadedPassword;
const SITE_URL = (process.env.SITE_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const PDF_TOKEN_MINUTES = 1440; // 24 Hours

/* --- CONSTANTS --- */
const PAPERS = [
  { slug: "plural-intelligence", title: "Plural Intelligence", file: "plural-intelligence.pdf" },
  { slug: "governance-first-ai", title: "Governance-First AI", file: "governance-first-ai.pdf" },
  { slug: "decision-systems-for-boards", title: "Decision Systems for Boards", file: "decision-systems-for-boards.pdf" },
  { slug: "ethics-without-ideology", title: "Ethics Without Ideology", file: "ethics-without-ideology.pdf" },
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
  if (raw) {
    raw.split(";").forEach((c) => {
      const [k, ...rest] = c.split("=");
      req.cookies[k.trim()] = decodeURIComponent(rest.join("=") || "");
    });
  }
  next();
});

/* --- FILE DATABASE HELPERS --- */
function readNDJSON(filePath) {
  if (!fs.existsSync(filePath)) return [];
  try {
    return fs.readFileSync(filePath, "utf-8")
      .trim()
      .split("\n")
      .map(line => { try { return JSON.parse(line); } catch (e) { return null; } })
      .filter(Boolean);
  } catch (e) {
    console.error(`Read error ${filePath}:`, e.message);
    return [];
  }
}

function appendNDJSON(filePath, record) {
  try {
    fs.appendFileSync(filePath, JSON.stringify(record) + "\n");
    return true;
  } catch (e) { return false; }
}

function updateNDJSON(filePath, records) {
  try {
    const content = records.map(r => JSON.stringify(r)).join("\n") + "\n";
    fs.writeFileSync(filePath, content);
    return true;
  } catch (e) { return false; }
}

function readJSON(filePath) {
  if (!fs.existsSync(filePath)) return null;
  try { return JSON.parse(fs.readFileSync(filePath, "utf-8")); } catch(e) { return null; }
}
function writeJSON(filePath, data) {
  try { fs.writeFileSync(filePath, JSON.stringify(data, null, 2)); return true; } catch(e) { return false; }
}

function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
}

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

/* --- PDF CONTROL HELPERS --- */
function getPaperConfig() {
  const cfg = readJSON(PAPERS_CONFIG_FILE);
  return cfg || { disabled: [] };
}

function isPaperEnabled(slug) {
  const cfg = getPaperConfig();
  return !cfg.disabled.includes(slug);
}

function togglePaper(slug) {
  const cfg = getPaperConfig();
  if (cfg.disabled.includes(slug)) {
    cfg.disabled = cfg.disabled.filter(s => s !== slug); // Enable
  } else {
    cfg.disabled.push(slug); // Disable
  }
  writeJSON(PAPERS_CONFIG_FILE, cfg);
}

/* --- VALIDATION HELPERS (NEW) --- */
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidLinkedIn(url) {
  if (!url) return true; // Optional field
  return /linkedin\.com\//.test(url);
}

/* --- UTILS --- */
function site() { return { name: "Atmakosh LLM", tagline: "The Soul-Repository AI" }; }
function hash(v) { return crypto.createHash("sha256").update(v).digest("hex"); }
function isAdmin(req) { return req.cookies.admin === hash(ADMIN_PASSWORD); }

function getIP(req) {
  const xf = String(req.headers["x-forwarded-for"] || "");
  return xf ? xf.split(",")[0].trim() : String(req.socket.remoteAddress || "").slice(0, 80);
}

function getUA(req) { return String(req.headers["user-agent"] || "").slice(0, 255); }

async function audit(req, event, meta = {}) {
  const record = {
    event,
    actor: "system",
    ip: getIP(req),
    user_agent: getUA(req),
    meta,
    created_at: new Date().toISOString()
  };
  appendNDJSON(AUDIT_FILE, record);
}

function mailer() {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  if (!host || !user || !pass) return null;
  return nodemailer.createTransport({ host, port, secure: false, auth: { user, pass } });
}

function getEmailTemplateHelper(name) {
  let templates = readJSON(TEMPLATES_FILE);
  if (!templates) {
    templates = [
      { name: "invite_approved", subject: "Your Atmakosh LLM preview access is approved", body_text: "Your access is approved. Visit: {{ACCESS_URL}}" },
      { name: "invite_received", subject: "Your Atmakosh LLM invitation request has been received", body_text: "We received your request." }
    ];
    writeJSON(TEMPLATES_FILE, templates);
  }
  return templates.find(t => t.name === name);
}

async function sendApprovalEmail(toEmail, opts = {}) {
  const transport = mailer();
  if (!transport) return;

  const tpl = getEmailTemplateHelper("invite_approved");
  const accessUrl = `${SITE_URL}/whitepapers/access`;
  
  const defaultText = `Your Atmakosh LLM preview access has been approved.\n\nAccess: ${accessUrl}`;
  let text = (tpl && tpl.body_text) ? tpl.body_text : defaultText;
  text = text.replace(/\{\{ACCESS_URL\}\}/g, accessUrl);
  
  const subject = (tpl && tpl.subject) ? tpl.subject : "Your Atmakosh LLM preview access is approved";

  const html = `
  <div style="font-family: -apple-system, sans-serif; background:#0b1024; color:#eaf0ff; padding:32px;">
    <div style="max-width:560px; margin:0 auto; background:linear-gradient(180deg, rgba(40,80,200,.35), rgba(20,40,120,.35)); border-radius:12px; padding:28px;">
      <h2 style="margin-top:0;">Access Approved</h2>
      <p>Hello ${opts.name || "there"},</p>
      <p>You can now access whitepapers.</p>
      <p><a href="${accessUrl}" style="color:#5b7cff;">Access Whitepapers</a></p>
    </div>
  </div>`;

  try {
    await transport.sendMail({ from: process.env.SMTP_FROM || process.env.SMTP_USER, to: toEmail, subject, text, html });
  } catch (e) { console.error("Email send failed:", e.message); }
}

async function sendInviteReceivedEmail(name, toEmail) {
  const transport = mailer();
  if (!transport) return;
  const tpl = getEmailTemplateHelper("invite_received");
  const subject = tpl ? tpl.subject : "Your Atmakosh LLM invitation request has been received";
  const text = tpl ? tpl.body_text : `Hello ${name || "there"}, we received your request.`;

  try {
    await transport.sendMail({ from: process.env.SMTP_FROM || process.env.SMTP_USER, to: toEmail, subject, text });
  } catch (e) { console.error("Receipt email failed:", e.message); }
}

function scoreInvite(intent = "") {
  let score = 0;
  const text = String(intent || "").toLowerCase();
  if (text.includes("governance")) score += 2;
  if (text.includes("ethics")) score += 2;
  if (text.includes("board") || text.includes("executive")) score += 1;
  if (text.length > 200) score += 1;
  return score;
}

const generalLimiter = rateLimit({ windowMs: 60 * 1000, max: 120 });
const accessLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 20 });
const downloadLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 30 });
const statusLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });

app.use(generalLimiter);

app.use((req, res, next) => {
  res.locals.SITE = site();
  res.locals.SITE_URL = SITE_URL;
  res.locals.path = req.path;
  res.locals.META = null;
  next();
});

app.use((req, res, next) => {
  const p = req.path || "";
  const isPrivate = p.startsWith("/admin") || p.startsWith("/download") || p.startsWith("/whitepapers/access");
  if (isPrivate) res.setHeader("X-Robots-Tag", "noindex, nofollow, noarchive");
  next();
});

/* PUBLIC ROUTES */
app.get("/", (req, res) => res.render("pages/home"));
app.get("/invite", (req, res) => res.render("pages/invite", { query: req.query }));
app.get("/whitepapers", (req, res) => res.render("pages/whitepapers", { papers: PAPERS }));
app.get("/leadership", (req, res) => res.render("pages/leadership"));
app.get("/terms", (req, res) => res.render("pages/terms"));
app.get("/why-atmakosh", (req, res) => res.render("pages/why-atmakosh"));
app.get("/whitepaper-vision", (req, res) => res.render("pages/whitepaper-vision"));

app.get("/team", (req, res) => res.redirect(301, "/leadership"));
app.get("/terms-of-use", (req, res) => res.redirect(301, "/terms"));
app.get("/why", (req, res) => res.redirect(301, "/why-atmakosh"));
app.get("/about", (req, res) => res.redirect(301, "/why-atmakosh"));
app.get("/vision", (req, res) => res.redirect(301, "/whitepaper-vision"));

/* ROBUST INVITE HANDLER (WITH VALIDATION) */
app.post("/api/invite", async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const linkedin = String(req.body.linkedin || "").trim();
  const intent = String(req.body.intent || "").trim();
  const score = scoreInvite(intent);

  if (!email) return res.status(400).send("Email is required");

  // 1. Validation Logic
  if (!isValidEmail(email)) {
    return res.redirect("/invite?error=invalid_email");
  }
  if (linkedin && !isValidLinkedIn(linkedin)) {
    return res.redirect("/invite?error=invalid_linkedin");
  }

  // 2. Check duplicate
  const records = readNDJSON(INVITES_FILE);
  if (records.find(r => r.email === email)) {
    await audit(req, "invite_duplicate", { email });
    return res.redirect("/invite?duplicate=1");
  }

  // 3. Create Record
  const newInvite = {
    id: generateId(),
    name,
    email,
    linkedin,
    intent,
    score,
    status: 'pending',
    created_at: new Date().toISOString()
  };

  if (!appendNDJSON(INVITES_FILE, newInvite)) return res.status(500).send("System error saving invite.");

  audit(req, "invite_submitted", { email });
  sendInviteReceivedEmail(name, email);

  return res.redirect("/invite?submitted=1");
});

/* SECURE DOWNLOADS (24h Window & Admin Control) */
app.get("/whitepapers/access", accessLimiter, (req, res) => {
  res.locals.META = { robots: "noindex" };
  res.render("pages/whitepapers-access", { papers: null, error: null, notice: null });
});

app.post("/whitepapers/access", accessLimiter, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  
  const invites = readNDJSON(INVITES_FILE);
  // Find approved invite. Using findIndex to update timestamp if needed.
  const idx = invites.findIndex(r => r.email === email && r.status === 'approved');

  if (idx === -1) {
    return res.render("pages/whitepapers-access", {
      papers: null,
      error: "Access not approved. Please wait for approval.",
      notice: null
    });
  }

  const userInvite = invites[idx];
  const now = Date.now();

  // 1. Check/Start 24-Hour Timer
  if (userInvite.access_started_at) {
    const startTime = new Date(userInvite.access_started_at).getTime();
    const limit = 24 * 60 * 60 * 1000; // 24 hours
    if ((now - startTime) > limit) {
      return res.render("pages/whitepapers-access", { 
        papers: null, 
        error: "Your 24-hour access window has expired. Access revoked.",
        notice: null
      });
    }
  } else {
    // First access: Start timer
    userInvite.access_started_at = new Date().toISOString();
    invites[idx] = userInvite;
    updateNDJSON(INVITES_FILE, invites);
  }

  // 2. Generate Tokens (only for enabled papers)
  const links = [];
  const expiresAt = new Date(now + PDF_TOKEN_MINUTES * 60 * 1000).toISOString();
  const ip = getIP(req);
  const ua = getUA(req);

  PAPERS.forEach(p => {
    if (!isPaperEnabled(p.slug)) return; // Skip disabled

    const token = crypto.randomBytes(24).toString("hex");
    const tokenRecord = {
      email, paper: p.slug, token, expires_at: expiresAt, ip, user_agent: ua, used_at: null
    };
    appendNDJSON(TOKENS_FILE, tokenRecord);
    links.push({ title: p.title, url: `${SITE_URL}/download/${token}` });
  });

  if (links.length === 0) {
    return res.render("pages/whitepapers-access", { 
      papers: null, error: "No whitepapers are currently available.", notice: null 
    });
  }

  await audit(req, "pdf_token_issued", { email });
  
  res.render("pages/whitepapers-access", { 
    papers: links, 
    error: null,
    notice: "Notice: You have access to these whitepapers for 24 hours. After that, your access will expire."
  });
});

app.get("/download/:token", downloadLimiter, async (req, res) => {
  const token = req.params.token;
  const tokens = readNDJSON(TOKENS_FILE);
  const idx = tokens.findIndex(t => t.token === token);

  if (idx === -1) return res.status(403).send("Access denied");
  const t = tokens[idx];
  if (t.used_at) return res.status(403).send("Link already used");
  if (new Date() > new Date(t.expires_at)) return res.status(403).send("Link expired");
  if ((t.ip && t.ip !== getIP(req)) || (t.user_agent && t.user_agent !== getUA(req))) {
    return res.status(403).send("Access denied (IP Mismatch)");
  }

  // Check if admin disabled the paper
  if (!isPaperEnabled(t.paper)) return res.status(403).send("This document is currently unavailable.");

  t.used_at = new Date().toISOString();
  tokens[tokenIdx] = t;
  updateNDJSON(TOKENS_FILE, tokens);

  const p = PAPERS.find(x => x.slug === t.paper);
  if (!p) return res.status(404).send("File not found");

  const filePath = path.join(__dirname, "private", "pdfs", p.file);
  if (fs.existsSync(filePath)) res.download(filePath);
  else res.status(404).send("File not found");
});

/* ADMIN */
app.get("/admin", (req, res) => {
  res.setHeader("X-Robots-Tag", "noindex, nofollow, noarchive");
  res.render("pages/admin-login", { error: null });
});

app.post("/admin", async (req, res) => {
  const input = String(req.body.password || "").trim();
  if (input === ADMIN_PASSWORD) {
    res.setHeader("Set-Cookie", `admin=${hash(ADMIN_PASSWORD)}; HttpOnly; Path=/; SameSite=Lax`);
    await audit(req, "admin_login", { ok: true });
    return res.redirect("/admin/invites");
  }
  await audit(req, "admin_login_failed", { ok: false });
  res.render("pages/admin-login", { error: "Invalid password" });
});

app.get("/admin/logout", async (req, res) => {
  res.setHeader("Set-Cookie", "admin=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax");
  await audit(req, "admin_logout", {});
  res.redirect("/");
});

app.get("/admin/invites", (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");
  const records = readNDJSON(INVITES_FILE).sort((a,b) => new Date(b.created_at) - new Date(a.created_at));
  res.render("pages/admin-invites", { rows: records });
});

app.post("/admin/invite/:id/approve", async (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");
  const id = req.params.id;
  const adminNote = req.body.admin_note;

  const records = readNDJSON(INVITES_FILE);
  let targetEmail = null;
  let targetName = null;

  const updated = records.map(r => {
    if (r.id === id) {
      r.status = 'approved';
      r.admin_note = adminNote;
      targetEmail = r.email;
      targetName = r.name;
    }
    return r;
  });

  updateNDJSON(INVITES_FILE, updated);
  if (targetEmail) {
    await sendApprovalEmail(targetEmail, { name: targetName });
    audit(req, "invite_approved", { email: targetEmail });
  }
  res.redirect("/admin/invites");
});

app.post("/admin/invite/:id/reject", async (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");
  const id = req.params.id;
  const records = readNDJSON(INVITES_FILE);
  const updated = records.map(r => { if (r.id === id) r.status = 'rejected'; return r; });
  updateNDJSON(INVITES_FILE, updated);
  audit(req, "invite_rejected", { id });
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

// Admin Route to Disable Papers
app.get("/admin/papers", (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");
  const cfg = getPaperConfig();
  res.send(`
    <h1>Manage Whitepapers</h1>
    <ul>
      ${PAPERS.map(p => `
        <li>
          <strong>${p.title}</strong> 
          [${cfg.disabled.includes(p.slug) ? "<span style='color:red'>DISABLED</span>" : "<span style='color:green'>ACTIVE</span>"}]
          <form method="POST" action="/admin/papers/${p.slug}/toggle" style="display:inline">
            <button>${cfg.disabled.includes(p.slug) ? "Enable" : "Disable"}</button>
          </form>
        </li>
      `).join("")}
    </ul>
    <a href="/admin/invites">Back to Dashboard</a>
  `);
});

app.post("/admin/papers/:slug/toggle", (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");
  togglePaper(req.params.slug);
  res.redirect("/admin/papers");
});

app.get("/admin/email-templates", (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");
  getEmailTemplateHelper("init");
  const rows = readJSON(TEMPLATES_FILE) || [];
  res.render("pages/admin-email-templates", { rows });
});

app.post("/admin/email-templates/:name", (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");
  const { subject, body_text } = req.body;
  const name = req.params.name;
  let rows = readJSON(TEMPLATES_FILE) || [];
  const idx = rows.findIndex(r => r.name === name);
  if (idx > -1) {
    rows[idx].subject = subject;
    rows[idx].body_text = body_text;
  } else {
    rows.push({ name, subject, body_text });
  }
  writeJSON(TEMPLATES_FILE, rows);
  audit(req, "email_template_updated", { name });
  res.redirect("/admin/email-templates");
});

app.get("/admin/invites.csv", (req, res) => {
  if (!isAdmin(req)) return res.status(403).send("Forbidden");
  const rows = readNDJSON(INVITES_FILE).sort((a,b) => new Date(b.created_at) - new Date(a.created_at));
  const header = "id,name,email,linkedin,status,score,created_at\n";
  const csv = header + rows.map(r => {
    const safeName = String(r.name || "").replace(/"/g, '""');
    return `${r.id},"${safeName}","${r.email}","${r.linkedin||''}",${r.status},${r.score},${r.created_at}`;
  }).join("\n");
  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", "attachment; filename=invites.csv");
  res.send(csv);
});

app.get("/admin/audit.csv", (req, res) => {
  if (!isAdmin(req)) return res.status(403).send("Forbidden");
  const rows = readNDJSON(AUDIT_FILE).reverse();
  const header = "event,actor,ip,user_agent,created_at\n";
  const csv = header + rows.map(r => {
    return `"${r.event}","${r.actor}","${r.ip}","${r.user_agent}",${r.created_at}`;
  }).join("\n");
  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", "attachment; filename=audit_log.csv");
  res.send(csv);
});

app.get("/invite/status", statusLimiter, (req, res) => {
  res.locals.META = { title: "Check Status", description: "Status check", canonical: `${SITE_URL}/invite/status` };
  res.render("pages/invite-status", { result: null, error: null });
});

app.post("/invite/status", statusLimiter, (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const records = readNDJSON(INVITES_FILE);
  const match = records.reverse().find(r => r.email === email);
  if (!match) return res.render("pages/invite-status", { result: null, error: "No request found." });
  res.render("pages/invite-status", { result: match, error: null });
});

app.get("/sitemap.xml", (req, res) => {
  const urls = [
    `${SITE_URL}/`, `${SITE_URL}/invite`, `${SITE_URL}/whitepapers`,
    `${SITE_URL}/leadership`, `${SITE_URL}/terms`
  ];
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map(u => `<url><loc>${u}</loc></url>`).join("\n")}
</urlset>`;
  res.type("application/xml").send(xml);
});

app.get("/healthz", (req, res) => {
  try {
    fs.accessSync(DATA_DIR, fs.constants.W_OK);
    res.json({ ok: true, service: "atmakosh-llm-site", storage: "writable", ts: new Date().toISOString() });
  } catch (e) {
    res.status(500).json({ ok: false, error: "Storage Read-only", ts: new Date().toISOString() });
  }
});

app.get("/debug/db-info", (req, res) => {
  res.json({ ok: true, mode: "filesystem", storage_path: DATA_DIR });
});

app.listen(PORT, () => console.log(`Atmakosh site running on ${PORT}`));

app.use((req, res) => { res.status(404); res.render("pages/404"); });
