require("dotenv").config();

const path = require("path");
const fs = require("fs");
const express = require("express");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

// DATABASE REPLACED WITH FILE SYSTEM
// const pool = require("./db"); 

const app = express();
const PORT = process.env.PORT || 3000;

/* --- DATA STORAGE PATHS --- */
// Ensure data directory exists
const DATA_DIR = path.join(__dirname, "data");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// File paths for our JSON "tables"
const INVITES_FILE = path.join(DATA_DIR, "invites.ndjson");
const TOKENS_FILE = path.join(DATA_DIR, "tokens.ndjson");
const AUDIT_FILE = path.join(DATA_DIR, "audit.ndjson");
const TEMPLATES_FILE = path.join(DATA_DIR, "email_templates.json");

/* --- CONFIG --- */
// Fix: Trim whitespace to prevent copy-paste errors
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || "changeme").trim();
console.log(`Admin Password Loaded. Length: ${ADMIN_PASSWORD.length} chars`);

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

// Cookie Parser
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

// Read Append-Only Logs (NDJSON) - Used for Invites, Audit, Tokens
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

// Append a single record (INSERT)
function appendNDJSON(filePath, record) {
  try {
    fs.appendFileSync(filePath, JSON.stringify(record) + "\n");
    return true;
  } catch (e) { return false; }
}

// Rewrite the file (UPDATE)
function updateNDJSON(filePath, records) {
  try {
    const content = records.map(r => JSON.stringify(r)).join("\n") + "\n";
    fs.writeFileSync(filePath, content);
    return true;
  } catch (e) { return false; }
}

// Read/Write Standard JSON (Used for Email Templates)
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

function site() {
  return { name: "Atmakosh LLM", tagline: "The Soul-Repository AI" };
}

function hash(v) {
  return crypto.createHash("sha256").update(v).digest("hex");
}

function isAdmin(req) {
  return req.cookies.admin === hash(ADMIN_PASSWORD);
}

/* --- AUDIT & UTILS --- */

function getIP(req) {
  const xf = String(req.headers["x-forwarded-for"] || "");
  return xf ? xf.split(",")[0].trim() : String(req.socket.remoteAddress || "").slice(0, 80);
}

function getUA(req) {
  return String(req.headers["user-agent"] || "").slice(0, 255);
}

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

/* --- EMAIL SYSTEM --- */

function mailer() {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const secure = String(process.env.SMTP_SECURE || "false").toLowerCase() === "true";

  if (!host || !user || !pass) return null;
  return nodemailer.createTransport({ host, port, secure, auth: { user, pass } });
}

// Get Template from JSON file or return default (DB Replacement)
function getEmailTemplateHelper(name) {
  let templates = readJSON(TEMPLATES_FILE);
  if (!templates) {
    // Default templates if file doesn't exist yet
    templates = [
      { name: "invite_approved", subject: "Your Atmakosh LLM preview access is approved", body_text: "Your access is approved. Visit: {{ACCESS_URL}}" },
      { name: "invite_received", subject: "Your Atmakosh LLM invitation request has been received", body_text: "We received your request." }
    ];
    writeJSON(TEMPLATES_FILE, templates);
  }
  return templates.find(t => t.name === name) || null;
}

async function sendApprovalEmail(toEmail, opts = {}) {
  const transport = mailer();
  if (!transport) return;

  const tpl = getEmailTemplateHelper("invite_approved");
  const accessUrl = `${SITE_URL}/whitepapers/access`;
  
  const defaultText = `Your Atmakosh LLM preview access has been approved.\n\nAccess: ${accessUrl}`;
  let text = (tpl && tpl.body_text) ? tpl.body_text : defaultText;
  
  // Replace variables
  text = text.replace(/\{\{ACCESS_URL\}\}/g, accessUrl);
  
  const subject = (tpl && tpl.subject) ? tpl.subject : "Your Atmakosh LLM preview access is approved";

  // Use HTML function for nice formatting
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

/* Whitepapers catalog */
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
  if (text.includes("board") || text.includes("executive")) score += 1;
  if (text.length > 200) score += 1;
  return score;
}

/* Rate limiting */
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
app.get("/", (req, res) => {
  res.locals.META = { title: "Atmakosh LLM", description: "Principled Intelligence", canonical: `${SITE_URL}/` };
  res.render("pages/home");
});

app.get("/invite", (req, res) => {
  res.locals.META = { title: "Request Invitation", description: "Request access", canonical: `${SITE_URL}/invite` };
  res.render("pages/invite", { query: req.query });
});

app.get("/whitepapers", (req, res) => {
  res.locals.META = { title: "Whitepapers", description: "Frameworks", canonical: `${SITE_URL}/whitepapers` };
  res.render("pages/whitepapers", { papers: PAPERS });
});

/* ROBUST INVITE HANDLER (FILE SYSTEM) */
app.post("/api/invite", async (req, res) => {
  const name = String(req.body.name || "").trim() || null;
  const email = String(req.body.email || "").trim().toLowerCase();
  const intent = String(req.body.intent || "").trim() || null;
  const score = scoreInvite(intent);

  if (!email) return res.status(400).send("Email is required");

  // Read existing invites to check for duplicates
  const records = readNDJSON(INVITES_FILE);
  if (records.find(r => r.email === email)) {
    await audit(req, "invite_duplicate", { email });
    return res.redirect("/invite?duplicate=1");
  }

  // Create new record
  const newInvite = {
    id: generateId(),
    name,
    email,
    intent,
    score,
    status: 'pending',
    created_at: new Date().toISOString()
  };

  if (!appendNDJSON(INVITES_FILE, newInvite)) {
    return res.status(500).send("System error saving invite.");
  }

  // Success Actions
  audit(req, "invite_submitted", { email });
  sendInviteReceivedEmail(name, email);

  return res.redirect("/invite?submitted=1");
});

/* SECURE DOWNLOADS (FILE SYSTEM) */
app.get("/whitepapers/access", accessLimiter, (req, res) => {
  res.locals.META = { robots: "noindex" };
  res.render("pages/whitepapers-access", { papers: null, error: null });
});

app.post("/whitepapers/access", accessLimiter, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  
  // Check approval in JSON file
  const invites = readNDJSON(INVITES_FILE);
  // Sort by date desc to get latest
  const userInvite = invites.reverse().find(r => r.email === email && r.status === 'approved');

  if (!userInvite) {
    return res.render("pages/whitepapers-access", {
      papers: null,
      error: "Access not approved. Please wait for approval.",
    });
  }

  const links = [];
  const expiresAt = new Date(Date.now() + PDF_TOKEN_MINUTES * 60 * 1000).toISOString();
  const ip = getIP(req);
  const ua = getUA(req);

  // Generate tokens for each paper
  PAPERS.forEach(p => {
    const token = crypto.randomBytes(24).toString("hex");
    const tokenRecord = {
      email,
      paper: p.slug,
      token,
      expires_at: expiresAt,
      ip,
      user_agent: ua,
      used_at: null
    };
    appendNDJSON(TOKENS_FILE, tokenRecord);
    links.push({ title: p.title, url: `${SITE_URL}/download/${token}` });
  });

  await audit(req, "pdf_token_issued", { email });
  res.render("pages/whitepapers-access", { papers: links, error: null });
});

app.get("/download/:token", downloadLimiter, async (req, res) => {
  const token = req.params.token;
  const ip = getIP(req);
  const ua = getUA(req);

  const tokens = readNDJSON(TOKENS_FILE);
  const tokenIdx = tokens.findIndex(t => t.token === token);

  if (tokenIdx === -1) return res.status(403).send("Access denied");

  const t = tokens[tokenIdx];
  if (t.used_at) return res.status(403).send("Link already used");
  if (new Date() > new Date(t.expires_at)) return res.status(403).send("Link expired");

  if ((t.ip && t.ip !== ip) || (t.user_agent && t.user_agent !== ua)) {
    return res.status(403).send("Access denied (IP Mismatch)");
  }

  // Update usage (Rewrite file)
  t.used_at = new Date().toISOString();
  tokens[tokenIdx] = t;
  updateNDJSON(TOKENS_FILE, tokens);

  const paper = PAPERS.find(p => p.slug === t.paper);
  if (!paper) return res.status(404).send("File not found");

  const filePath = path.join(__dirname, "private", "pdfs", paper.file);
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
  // Read and sort invites
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
  const updated = records.map(r => {
    if (r.id === id) r.status = 'rejected';
    return r;
  });
  
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

app.get("/admin/email-templates", (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");
  // Ensure default templates exist
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
  
  const header = "id,name,email,status,score,created_at\n";
  const csv = header + rows.map(r => {
    const safeName = String(r.name || "").replace(/"/g, '""');
    return `${r.id},"${safeName}","${r.email}",${r.status},${r.score},${r.created_at}`;
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

/* Health check (Now checks File System instead of DB) */
app.get("/healthz", (req, res) => {
  try {
    // Check if we can write to the data directory
    fs.accessSync(DATA_DIR, fs.constants.W_OK);
    res.json({ ok: true, service: "atmakosh-llm-site", storage: "writable", ts: new Date().toISOString() });
  } catch (e) {
    res.status(500).json({ ok: false, error: "Storage Read-only", ts: new Date().toISOString() });
  }
});

/* Debug routes adapted for File System info */
app.get("/debug/db-info", (req, res) => {
  res.json({ ok: true, mode: "filesystem", storage_path: DATA_DIR });
});

app.listen(PORT, () => console.log(`Atmakosh site running on ${PORT}`));

app.get("/why-atmakosh", (req, res) => {
  res.locals.META = { title: "Why Atmakosh", description: "Why", canonical: `${SITE_URL}/why-atmakosh` };
  res.render("pages/why-atmakosh");
});
app.get("/whitepaper-vision", (req, res) => {
  res.locals.META = { title: "Vision", description: "Vision", canonical: `${SITE_URL}/whitepaper-vision` };
  res.render("pages/whitepaper-vision");
});
app.get("/leadership", (req, res) => {
  res.locals.META = { title: "Leadership", description: "Leadership", canonical: `${SITE_URL}/leadership` };
  res.render("pages/leadership");
});
app.get("/team", (req, res) => res.redirect(301, "/leadership"));
app.get("/terms", (req, res) => {
  res.locals.META = { title: "Terms", description: "Terms", canonical: `${SITE_URL}/terms` };
  res.render("pages/terms");
});
app.get("/terms-of-use", (req, res) => res.redirect(301, "/terms"));
app.get("/why", (req, res) => res.redirect(301, "/why-atmakosh"));
app.get("/about", (req, res) => res.redirect(301, "/why-atmakosh"));
app.get("/vision", (req, res) => res.redirect(301, "/whitepaper-vision"));

app.use((req, res) => { res.status(404); res.render("pages/404"); });
