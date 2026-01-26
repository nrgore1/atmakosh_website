const path = require("path");
const fs = require("fs");
const express = require("express");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const pool = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "changeme";
const SITE_URL = (process.env.SITE_URL || `http://localhost:${PORT}`).replace(/\/$/, "");

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));

/* Simple cookie parser */
app.use((req, res, next) => {
  req.cookies = {};
  const raw = req.headers.cookie;
  if (raw) {
    raw.split(";").forEach(c => {
      const [k, ...rest] = c.split("=");
      req.cookies[k.trim()] = decodeURIComponent(rest.join("=") || "");
    });
  }
  next();
});

/* Helpers */
function site(){
  return { name: "Atmakosh LLM", tagline: "The Soul-Repository AI" };
}
function hash(v) {
  return crypto.createHash("sha256").update(v).digest("hex");
}
function isAdmin(req) {
  return req.cookies.admin === hash(ADMIN_PASSWORD);
}
function getIP(req) {
  return String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").slice(0, 80);
}
function getUA(req) {
  return String(req.headers["user-agent"] || "").slice(0, 255);
}
async function audit(req, event, meta = {}) {
  try {
    await pool.execute(
      "INSERT INTO audit_log (event, actor, ip, user_agent, meta) VALUES (?, ?, ?, ?, ?)",
      [event, "admin", getIP(req), getUA(req), JSON.stringify(meta)]
    );
  } catch (e) {
    console.error("Audit log failed:", e.message);
  }
}

/* Email (approval notifications) */
function mailer() {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const secure = String(process.env.SMTP_SECURE || "false").toLowerCase() === "true";

  if (!host || !user || !pass) return null;

  return nodemailer.createTransport({
    host,
    port,
    secure,
    auth: { user, pass }
  });
}

async function sendApprovalEmail(toEmail) {
  const transport = mailer();
  if (!transport) return;

  const from = process.env.SMTP_FROM || process.env.SMTP_USER;
  const subject = "Your Atmakosh LLM preview access is approved";
  const accessUrl = `${SITE_URL}/whitepapers/access`;

  const text =
`Your Atmakosh LLM preview access has been approved.

Access the whitepapers here:
${accessUrl}

Use the same email address you used in the invite request.

— Atmakosh Team`;

  try {
    await transport.sendMail({ from, to: toEmail, subject, text });
  } catch (e) {
    console.error("Email send failed:", e.message);
  }
}

/* Whitepapers catalog */
const PAPERS = [
  { slug: "plural-intelligence", title: "Plural Intelligence", file: "plural-intelligence.pdf" },
  { slug: "governance-first-ai", title: "Governance-First AI", file: "governance-first-ai.pdf" },
  { slug: "decision-systems-for-boards", title: "Decision Systems for Boards", file: "decision-systems-for-boards.pdf" },
  { slug: "ethics-without-ideology", title: "Ethics Without Ideology", file: "ethics-without-ideology.pdf" }
];

/* Public Routes */
app.get("/", (req, res) => res.render("pages/home", { SITE: site(), path: "/" }));
app.get("/invite", (req, res) => res.render("pages/invite", { SITE: site(), path: "/invite" }));
app.get("/whitepapers", (req, res) => res.render("pages/whitepapers", { SITE: site(), path: "/whitepapers", papers: PAPERS }));
app.get("/whitepapers/access", (req, res) => res.render("pages/whitepapers-access", { SITE: site(), path: "/whitepapers/access", papers: null, error: null }));
app.get("/leadership", (req, res) => res.render("pages/leadership", { SITE: site(), path: "/leadership" }));
app.get("/terms", (req, res) => res.render("pages/terms", { SITE: site(), path: "/terms" }));

/* Invite submission (MySQL) */
app.post("/api/invite", async (req, res) => {
  try {
    await pool.execute(
      "INSERT INTO invites (name, email, intent, status) VALUES (?, ?, ?, 'pending')",
      [req.body.name, req.body.email, req.body.intent]
    );
    res.redirect("/invite");
  } catch (err) {
    console.error("Invite insert failed:", err.message);
    res.status(500).send("Unable to process invite request");
  }
});

/* Whitepaper access: generate expiring token links for approved users */
app.post("/whitepapers/access", async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  if (!email) {
    return res.render("pages/whitepapers-access", { SITE: site(), path: "/whitepapers/access", papers: null, error: "Please enter your email." });
  }

  const [inv] = await pool.execute(
    "SELECT * FROM invites WHERE email=? AND status='approved' ORDER BY id DESC LIMIT 1",
    [email]
  );

  if (inv.length === 0) {
    return res.render("pages/whitepapers-access", {
      SITE: site(),
      path: "/whitepapers/access",
      papers: null,
      error: "Access not approved for this email yet. If you’ve requested an invite, please wait for approval."
    });
  }

  const links = [];
  const expiresMinutes = Number(process.env.PDF_TOKEN_MINUTES || 60);

  for (const p of PAPERS) {
    const token = crypto.randomBytes(24).toString("hex");
    const expiresAt = new Date(Date.now() + expiresMinutes * 60 * 1000);
    const expiresSQL = expiresAt.toISOString().slice(0, 19).replace("T", " ");

    await pool.execute(
      "INSERT INTO download_tokens (email, paper, token, expires_at) VALUES (?, ?, ?, ?)",
      [email, p.slug, token, expiresSQL]
    );

    links.push({
      title: p.title,
      url: `${SITE_URL}/download/${token}`
    });
  }

  // audit (token generation)
  try {
    await pool.execute(
      "INSERT INTO audit_log (event, actor, ip, user_agent, meta) VALUES (?, ?, ?, ?, ?)",
      ["pdf_token_issued", "system", getIP(req), getUA(req), JSON.stringify({ email })]
    );
  } catch (e) {}

  res.render("pages/whitepapers-access", { SITE: site(), path: "/whitepapers/access", papers: links, error: null });
});

/* Secure PDF delivery by token */
app.get("/download/:token", async (req, res) => {
  const token = String(req.params.token || "").trim();

  const [rows] = await pool.execute(
    "SELECT * FROM download_tokens WHERE token=? LIMIT 1",
    [token]
  );

  if (rows.length === 0) return res.status(403).send("Access denied");

  const row = rows[0];
  const exp = new Date(row.expires_at);
  if (Date.now() > exp.getTime()) return res.status(403).send("Link expired");

  const paper = PAPERS.find(p => p.slug === row.paper);
  if (!paper) return res.status(404).send("File not found");

  const filePath = path.join(__dirname, "private", "pdfs", paper.file);
  if (!fs.existsSync(filePath)) return res.status(404).send("File not found");

  // audit download
  try {
    await pool.execute(
      "INSERT INTO audit_log (event, actor, ip, user_agent, meta) VALUES (?, ?, ?, ?, ?)",
      ["pdf_download", "user", getIP(req), getUA(req), JSON.stringify({ email: row.email, paper: row.paper })]
    );
  } catch (e) {}

  res.download(filePath);
});

/* Admin */
app.get("/admin", (req, res) => {
  res.render("pages/admin-login", { SITE: site(), error: null });
});

app.post("/admin", async (req, res) => {
  if (req.body.password === ADMIN_PASSWORD) {
    res.setHeader("Set-Cookie", `admin=${hash(ADMIN_PASSWORD)}; HttpOnly; Path=/`);
    try {
      await pool.execute(
        "INSERT INTO audit_log (event, actor, ip, user_agent, meta) VALUES (?, ?, ?, ?, ?)",
        ["admin_login", "admin", getIP(req), getUA(req), JSON.stringify({ ok: true })]
      );
    } catch (e) {}
    return res.redirect("/admin/invites");
  }

  try {
    await pool.execute(
      "INSERT INTO audit_log (event, actor, ip, user_agent, meta) VALUES (?, ?, ?, ?, ?)",
      ["admin_login_failed", "admin", getIP(req), getUA(req), JSON.stringify({ ok: false })]
    );
  } catch (e) {}

  res.render("pages/admin-login", { SITE: site(), error: "Invalid password" });
});

app.get("/admin/logout", async (req, res) => {
  res.setHeader("Set-Cookie", "admin=; HttpOnly; Path=/; Max-Age=0");
  try {
    await pool.execute(
      "INSERT INTO audit_log (event, actor, ip, user_agent, meta) VALUES (?, ?, ?, ?, ?)",
      ["admin_logout", "admin", getIP(req), getUA(req), JSON.stringify({})]
    );
  } catch (e) {}
  res.redirect("/");
});

app.get("/admin/invites", async (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");

  const [rows] = await pool.execute(
    "SELECT * FROM invites ORDER BY created_at DESC"
  );

  res.render("pages/admin-invites", { SITE: site(), path: "/admin/invites", rows });
});

/* Approval actions + email notification + audit */
app.post("/admin/invite/:id/approve", async (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");

  const id = req.params.id;

  const [rows] = await pool.execute("SELECT * FROM invites WHERE id=? LIMIT 1", [id]);
  if (rows.length === 0) return res.redirect("/admin/invites");

  await pool.execute("UPDATE invites SET status='approved' WHERE id=?", [id]);

  await audit(req, "invite_approved", { id, email: rows[0].email });

  // email notification
  await sendApprovalEmail(rows[0].email);

  res.redirect("/admin/invites");
});

app.post("/admin/invite/:id/reject", async (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");

  const id = req.params.id;
  const [rows] = await pool.execute("SELECT * FROM invites WHERE id=? LIMIT 1", [id]);
  if (rows.length === 0) return res.redirect("/admin/invites");

  await pool.execute("UPDATE invites SET status='rejected' WHERE id=?", [id]);
  await audit(req, "invite_rejected", { id, email: rows[0].email });

  res.redirect("/admin/invites");
});

/* Health check + uptime monitoring */
app.get("/healthz", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      ok: true,
      service: "atmakosh-llm-site",
      db: "ok",
      ts: new Date().toISOString()
    });
  } catch (e) {
    res.status(500).json({
      ok: false,
      service: "atmakosh-llm-site",
      db: "down",
      error: e.message,
      ts: new Date().toISOString()
    });
  }
});

app.listen(PORT, () => console.log(`Atmakosh site running on ${PORT}`));
