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

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "changeme";
const SITE_URL = (process.env.SITE_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const PDF_TOKEN_MINUTES = Number(process.env.PDF_TOKEN_MINUTES || 60);

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// If behind proxy (Hostinger), trust it for IP + secure cookies
app.set("trust proxy", 1);

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Security headers
app.use(
  helmet({
    contentSecurityPolicy: false, // keep simple for now
  })
);

/* Simple cookie parser */
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

function site() {
  return { name: "Atmakosh LLM", tagline: "The Soul-Repository AI" };
}

function hash(v) {
  return crypto.createHash("sha256").update(v).digest("hex");
}

function isAdmin(req) {
  return req.cookies.admin === hash(ADMIN_PASSWORD);
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
    // do not block on audit failure
  }
}

/* Email */
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
    auth: { user, pass },
  });
}

async function getEmailTemplate(name) {
  try {
    const [rows] = await pool.execute("SELECT * FROM email_templates WHERE name=? LIMIT 1", [name]);
    return rows[0] || null;
  } catch (e) {
    return null;
  }
}

function approvalEmailHTML({ name }) {
  return `
  <div style="font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif;
              background:#0b1024; color:#eaf0ff; padding:32px;">
    <div style="max-width:560px; margin:0 auto;
                background:linear-gradient(180deg, rgba(40,80,200,.35), rgba(20,40,120,.35));
                border-radius:12px; padding:28px;
                box-shadow:0 20px 60px rgba(0,0,0,.35);">
      <h2 style="margin-top:0;">Your Atmakosh LLM access is approved</h2>
      <p>Hello ${name || "there"},</p>
      <p>You’ve been selected to participate in the Atmakosh LLM private preview.</p>
      <p>You can now access curated whitepapers and follow the instructions provided to begin using Atmakosh LLM.</p>
      <p style="margin-top:24px;">
        <a href="${SITE_URL}/whitepapers/access"
           style="display:inline-block; padding:12px 18px;
                  background:#5b7cff; color:#fff;
                  border-radius:8px; text-decoration:none;">
          Access Whitepapers
        </a>
      </p>
      <p style="opacity:.8; margin-top:28px;">— The Atmakosh LLM Team</p>
    </div>
  </div>
  `;
}

async function sendApprovalEmail(toEmail, opts = {}) {
  const transport = mailer();
  if (!transport) return;

  const from = process.env.SMTP_FROM || process.env.SMTP_USER;
  const defaultSubject = "Your Atmakosh LLM preview access is approved";
  const tpl = await getEmailTemplate("invite_approved");

  const accessUrl = `${SITE_URL}/whitepapers/access`;
  const text =
    (tpl && tpl.body_text)
      ? tpl.body_text.replace(/\{\{ACCESS_URL\}\}/g, accessUrl)
      : `Your Atmakosh LLM preview access has been approved.

Access the whitepapers here:
${accessUrl}

Use the same email address you used in the invite request.

— Atmakosh Team`;

  const subject = (tpl && tpl.subject) ? tpl.subject : defaultSubject;

  try {
    await transport.sendMail({
      from,
      to: toEmail,
      subject,
      text,
      html: approvalEmailHTML({ name: opts.name || "" })
    });
  } catch (e) {
    console.error("Email send failed:", e.message);
  }
}

async function sendInviteReceivedEmail(name, toEmail) {
  const transport = mailer();
  if (!transport) return;

  const from = process.env.SMTP_FROM || process.env.SMTP_USER;
  const subject = "Your Atmakosh LLM invitation request has been received";

  const text =
`Hello ${name || "there"},

Thank you for requesting an invitation to Atmakosh LLM.

We’ve successfully added your name and email to our invitation registry.

Atmakosh LLM is an invite-only research preview focused on ethical,
auditable, and principled AI reasoning inspired by Indian philosophy
and modern governance frameworks.

What happens next:
• Our team reviews requests on a rolling basis
• Selected participants will receive a follow-up invitation
• Approved users will gain access to curated whitepapers and
  instructions for participating in the Atmakosh LLM beta evaluation

If selected, you will receive a separate email with:
• Secure access instructions
• Whitepaper download links
• Guidance on how to use Atmakosh LLM during the evaluation

Thank you for your interest and patience.

— The Atmakosh LLM Team`;

  try {
    await transport.sendMail({ from, to: toEmail, subject, text });
  } catch (e) {
    console.error("Invite receipt email failed:", e.message);
  }
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
const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
});

const accessLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

const downloadLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
});

const statusLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(generalLimiter);

// SEO locals for every render
app.use((req, res, next) => {
  res.locals.SITE = site();
  res.locals.SITE_URL = SITE_URL;
  res.locals.path = req.path;
  res.locals.META = null;
  next();
});

// Noindex private routes
app.use((req, res, next) => {
  const p = req.path || "";
  const isPrivate =
    p.startsWith("/admin") ||
    p.startsWith("/download") ||
    p.startsWith("/whitepapers/access");
  if (isPrivate) {
    res.setHeader("X-Robots-Tag", "noindex, nofollow, noarchive");
  }
  next();
});

/* PUBLIC ROUTES */
app.get("/", (req, res) => {
  res.locals.META = {
    title: "Atmakosh LLM — Principled Intelligence for High-Stakes Decisions",
    description:
      "Atmakosh LLM is a Soul-Repository AI inspired by Indian philosophy, designed for ethical, restrained, and auditable reasoning. Invite-only preview opening shortly.",
    canonical: `${SITE_URL}/`,
  };
  res.render("pages/home");
});

app.get("/invite", (req, res) => {
  res.locals.META = {
    title: "Request Invitation — Atmakosh LLM",
    description:
      "Request an invitation to the private preview of Atmakosh LLM. Built for principled, auditable decision intelligence.",
    canonical: `${SITE_URL}/invite`,
  };
  res.render("pages/invite", { query: req.query });
});

app.get("/whitepapers", (req, res) => {
  res.locals.META = {
    title: "Whitepapers — Atmakosh LLM",
    description:
      "Thought leadership and frameworks behind Atmakosh LLM: governance-first AI, decision systems, and principled alignment.",
    canonical: `${SITE_URL}/whitepapers`,
  };
  res.render("pages/whitepapers", { papers: PAPERS });
});

app.get("/whitepapers/access", accessLimiter, (req, res) => {
  res.locals.META = {
    title: "Access PDFs — Atmakosh LLM",
    description:
      "Approved users can generate secure, expiring download links for Atmakosh LLM whitepapers.",
    canonical: `${SITE_URL}/whitepapers/access`,
    robots: "noindex,nofollow,noarchive",
  };
  res.render("pages/whitepapers-access", { papers: null, error: null });
});

app.post("/api/invite", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const intent = String(req.body.intent || "").trim();
    const score = scoreInvite(intent);

    if (!email) return res.status(400).send("Email is required");

    // Prefer inserting score if your schema has it; fall back if not.
    try {
      await pool.execute(
        "INSERT INTO invites (name, email, intent, status, score) VALUES (?, ?, ?, 'pending', ?)",
        [name, email, intent, score]
      );
    } catch (e) {
      // Older schema without 'score'
      await pool.execute(
        "INSERT INTO invites (name, email, intent, status) VALUES (?, ?, ?, 'pending')",
        [name, email, intent]
      );
    }

    await audit(req, "invite_submitted", { email });
    await sendInviteReceivedEmail(name, email);

    res.redirect("/invite?submitted=1");
  } catch (err) {
    console.error("Invite insert failed:", err.message);
    res.status(500).send("Unable to process invite request");
  }
});

/* Generate expiring, one-time, IP/UA-bound token links */
app.post("/whitepapers/access", accessLimiter, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  if (!email) {
    return res.render("pages/whitepapers-access", { papers: null, error: "Please enter your email." });
  }

  const [inv] = await pool.execute(
    "SELECT * FROM invites WHERE email=? AND status='approved' ORDER BY id DESC LIMIT 1",
    [email]
  );

  if (inv.length === 0) {
    return res.render("pages/whitepapers-access", {
      papers: null,
      error: "Access not approved for this email yet. If you’ve requested an invite, please wait for approval.",
    });
  }

  const ip = getIP(req);
  const ua = getUA(req);

  try {
    await pool.execute("DELETE FROM download_tokens WHERE email=? AND expires_at < NOW()", [email]);
  } catch (e) {}

  const links = [];
  const expiresAt = new Date(Date.now() + PDF_TOKEN_MINUTES * 60 * 1000);
  const expiresSQL = expiresAt.toISOString().slice(0, 19).replace("T", " ");

  for (const p of PAPERS) {
    const token = crypto.randomBytes(24).toString("hex");
    await pool.execute(
      "INSERT INTO download_tokens (email, paper, token, expires_at, ip, user_agent, used_at) VALUES (?, ?, ?, ?, ?, ?, NULL)",
      [email, p.slug, token, expiresSQL, ip, ua]
    );
    links.push({ title: p.title, url: `${SITE_URL}/download/${token}` });
  }

  await audit(req, "pdf_token_issued", { email });
  res.render("pages/whitepapers-access", { papers: links, error: null });
});

/* Secure PDF delivery: token must be valid, unexpired, unused, same IP+UA */
app.get("/download/:token", downloadLimiter, async (req, res) => {
  const token = String(req.params.token || "").trim();
  const ip = getIP(req);
  const ua = getUA(req);

  const [rows] = await pool.execute("SELECT * FROM download_tokens WHERE token=? LIMIT 1", [token]);
  if (rows.length === 0) return res.status(403).send("Access denied");

  const row = rows[0];
  if (row.used_at) return res.status(403).send("Link already used");

  const exp = new Date(row.expires_at);
  if (Date.now() > exp.getTime()) return res.status(403).send("Link expired");

  if ((row.ip && row.ip !== ip) || (row.user_agent && row.user_agent !== ua)) {
    await audit(req, "pdf_download_blocked_mismatch", { token, email: row.email, paper: row.paper });
    return res.status(403).send("Access denied");
  }

  const paper = PAPERS.find((p) => p.slug === row.paper);
  if (!paper) return res.status(404).send("File not found");

  const filePath = path.join(__dirname, "private", "pdfs", paper.file);
  if (!fs.existsSync(filePath)) return res.status(404).send("File not found");

  await pool.execute("UPDATE download_tokens SET used_at=NOW() WHERE token=?", [token]);
  await audit(req, "pdf_download", { email: row.email, paper: row.paper });

  res.download(filePath);
});

/* ADMIN */
app.get("/admin", (req, res) => {
  res.setHeader("X-Robots-Tag", "noindex, nofollow, noarchive");
  res.render("pages/admin-login", { error: null });
});

app.post("/admin", async (req, res) => {
  if (req.body.password === ADMIN_PASSWORD) {
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

app.get("/admin/invites", async (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");

  const [rows] = await pool.execute(
    "SELECT * FROM invites ORDER BY score DESC, created_at DESC"
  );

  res.render("pages/admin-invites", { rows });
});

/* Approval actions + email notification */
app.post("/admin/invite/:id/approve", async (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");

  const id = req.params.id;
  const note = String(req.body.admin_note || "").trim() || null;

  const [rows] = await pool.execute("SELECT * FROM invites WHERE id=? LIMIT 1", [id]);
  if (rows.length === 0) return res.redirect("/admin/invites");

  try {
    await pool.execute("UPDATE invites SET status='approved', admin_note=? WHERE id=?", [note, id]);
  } catch (e) {
    // If schema doesn't include admin_note
    await pool.execute("UPDATE invites SET status='approved' WHERE id=?", [id]);
  }

  await audit(req, "invite_approved", { id, email: rows[0].email });

  await sendApprovalEmail(rows[0].email, { name: rows[0].name || "" });
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

/* Admin invite analytics */
app.get("/admin/analytics", async (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");

  const [[counts]] = await pool.query(`
    SELECT
      COUNT(*) AS total,
      SUM(status='pending') AS pending,
      SUM(status='approved') AS approved,
      SUM(status='rejected') AS rejected
    FROM invites
  `);

  res.render("pages/admin-analytics", { counts });
});

/* Admin email templates */
app.get("/admin/email-templates", async (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");

  const [rows] = await pool.execute(
    "SELECT name, subject, body_text FROM email_templates ORDER BY name"
  );

  res.render("pages/admin-email-templates", { rows });
});

app.post("/admin/email-templates/:name", async (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");

  const { subject, body_text } = req.body;

  await pool.execute(
    "UPDATE email_templates SET subject=?, body_text=? WHERE name=?",
    [subject, body_text, req.params.name]
  );

  await audit(req, "email_template_updated", { name: req.params.name });
  res.redirect("/admin/email-templates");
});

/* Admin CSV export: invites */
app.get("/admin/invites.csv", async (req, res) => {
  if (!isAdmin(req)) return res.status(403).send("Forbidden");

  const [rows] = await pool.execute(
    "SELECT id, name, email, status, score, created_at FROM invites ORDER BY score DESC, created_at DESC"
  );

  const header = "id,name,email,status,score,created_at\n";
  const csv =
    header +
    rows
      .map((r) => {
        const safeName = String(r.name || "").replace(/"/g, '""');
        return `${r.id},"${safeName}","${r.email}",${r.status},${r.score ?? ""},${new Date(r.created_at).toISOString()}`;
      })
      .join("\n");

  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", "attachment; filename=invites.csv");
  res.send(csv);
});

/* Audit log export */
app.get("/admin/audit.csv", async (req, res) => {
  if (!isAdmin(req)) return res.status(403).send("Forbidden");

  const [rows] = await pool.execute(
    "SELECT event, actor, ip, user_agent, created_at FROM audit_log ORDER BY created_at DESC"
  );

  const header = "event,actor,ip,user_agent,created_at\n";
  const csv =
    header +
    rows
      .map((r) => {
        const created = new Date(r.created_at).toISOString();
        const ua = String(r.user_agent || "").replace(/"/g, '""');
        return `"${r.event}","${r.actor}","${r.ip}","${ua}",${created}`;
      })
      .join("\n");

  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", "attachment; filename=audit_log.csv");
  res.send(csv);
});

/* Invite status lookup (user-facing, read-only) */
app.get("/invite/status", statusLimiter, (req, res) => {
  res.locals.META = {
    title: "Check Invitation Status — Atmakosh LLM",
    description: "Check the status of your Atmakosh LLM invitation request.",
    canonical: `${SITE_URL}/invite/status`,
  };
  res.render("pages/invite-status", { result: null, error: null });
});

app.post("/invite/status", statusLimiter, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  if (!email) {
    return res.render("pages/invite-status", {
      result: null,
      error: "Please enter the email you used when requesting an invitation.",
    });
  }

  const [rows] = await pool.execute(
    "SELECT status, created_at FROM invites WHERE email=? ORDER BY id DESC LIMIT 1",
    [email]
  );

  if (rows.length === 0) {
    return res.render("pages/invite-status", {
      result: null,
      error: "No invitation request found for this email.",
    });
  }

  res.render("pages/invite-status", { error: null, result: rows[0] });
});

/* SITEMAP (SEO) - only public pages */
app.get("/sitemap.xml", (req, res) => {
  const urls = [
    `${SITE_URL}/`,
    `${SITE_URL}/invite`,
    `${SITE_URL}/whitepapers`,
    `${SITE_URL}/leadership`,
    `${SITE_URL}/terms`,
  ];

  const xml =
`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map((u) => `<url><loc>${u}</loc></url>`).join("\n")}
</urlset>`;

  res.type("application/xml").send(xml);
});

/* Health check (uptime monitoring) */
app.get("/healthz", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, service: "atmakosh-llm-site", db: "ok", ts: new Date().toISOString() });
  } catch (e) {
    res.status(500).json({
      ok: false,
      service: "atmakosh-llm-site",
      db: "down",
      error: e.message,
      ts: new Date().toISOString(),
    });
  }
});

app.listen(PORT, () => console.log(`Atmakosh site running on ${PORT}`));

function adminCookie(req) {
  const secure = req.secure ? "; Secure" : "";
  return `admin=${hash(ADMIN_PASSWORD)}; HttpOnly; Path=/; SameSite=Lax${secure}`;
}

app.get("/debug/db", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true });
  } catch (e) {
    logProdError("DB health check failed", e);
    res.status(500).json({ ok: false });
  }
});

app.get("/debug/db-info", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT DATABASE() AS db, USER() AS user");
    res.json({
      ok: true,
      database: rows[0].db,
      user: rows[0].user
    });
  } catch (e) {
    console.error("DB INFO FAILED:", e.code, e.sqlMessage);
    res.status(500).json({ ok: false });
  }
});

app.get("/why-atmakosh", (req, res) => {
  res.locals.META = {
    title: "Why Atmakosh — Thoughtful, Governed AI",
    description:
      "Why Atmakosh exists: a governance-first, explainable AI system built for high-stakes decisions.",
    canonical: `${SITE_URL}/why-atmakosh`,
  };
  res.render("pages/why-atmakosh");
});


app.get("/whitepaper-vision", (req, res) => {
  res.redirect(301, "/whitepapers");
});


app.get("/whitepaper-vision", (req, res) => {
  res.locals.META = {
    title: "Whitepaper Vision — Atmakosh LLM",
    description:
      "The vision behind Atmakosh whitepapers: governance-first AI, ethical reasoning, and accountable decision systems.",
    canonical: `${SITE_URL}/whitepaper-vision`,
  };
  res.render("pages/whitepaper-vision");
});


app.get("/leadership", (req, res) => {
  res.locals.META = {
    title: "Leadership — Atmakosh LLM",
    description:
      "Leadership and founding vision behind Atmakosh LLM — principled, governance-first artificial intelligence.",
    canonical: `${SITE_URL}/leadership`,
  };
  res.render("pages/leadership");
});


app.get("/team", (req, res) => res.redirect(301, "/leadership"));


app.get("/terms", (req, res) => {
  res.locals.META = {
    title: "Terms of Use — Atmakosh LLM",
    description:
      "Terms of use and legal conditions governing access to the Atmakosh LLM website and preview materials.",
    canonical: `${SITE_URL}/terms`,
  };
  res.render("pages/terms");
});


app.get("/terms-of-use", (req, res) => res.redirect(301, "/terms"));

