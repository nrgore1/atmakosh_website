const path = require("path");
const fs = require("fs");
const express = require("express");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Ekveeramatakija1!!!!";

const DATA_DIR = path.join(__dirname, "data");
const INVITES_FILE = path.join(DATA_DIR, "invites.ndjson");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(INVITES_FILE)) fs.writeFileSync(INVITES_FILE, "", "utf8");

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
      const [k, v] = c.split("=");
      req.cookies[k.trim()] = decodeURIComponent(v);
    });
  }
  next();
});

/* AUTH HELPERS */
function isAdmin(req) {
  return req.cookies.admin === hash(ADMIN_PASSWORD);
}
function hash(v) {
  return crypto.createHash("sha256").update(v).digest("hex");
}

/* SITE META */
function site(){
  return {
    name: "Atmakosh LLM",
    tagline: "The Soul-Repository AI"
  };
}

/* PUBLIC ROUTES */
app.get("/", (req, res) =>
  res.render("pages/home", { SITE: site(), path: "/" })
);

app.get("/invite", (req, res) =>
  res.render("pages/invite", { SITE: site(), path: "/invite" })
);

app.get("/whitepapers", (req, res) =>
  res.render("pages/whitepapers", { SITE: site(), path: "/whitepapers" })
);

app.get("/leadership", (req, res) =>
  res.render("pages/leadership", { SITE: site(), path: "/leadership" })
);

app.get("/terms", (req, res) =>
  res.render("pages/terms", { SITE: site(), path: "/terms" })
);

/* INVITE SUBMISSION */
app.post("/api/invite", (req, res) => {
  const entry = {
    ts: new Date().toISOString(),
    name: req.body.name,
    email: req.body.email,
    intent: req.body.intent
  };
  fs.appendFileSync(INVITES_FILE, JSON.stringify(entry) + "\n");
  res.redirect("/invite");
});

/* ADMIN LOGIN */
app.get("/admin", (req, res) => {
  res.render("pages/admin-login", {
    SITE: site(),
    error: null
  });
});

app.post("/admin", (req, res) => {
  if (req.body.password === ADMIN_PASSWORD) {
    res.setHeader(
      "Set-Cookie",
      `admin=${hash(ADMIN_PASSWORD)}; HttpOnly; Path=/`
    );
    return res.redirect("/admin/invites");
  }
  res.render("pages/admin-login", {
    SITE: site(),
    error: "Invalid password"
  });
});

/* ADMIN DASHBOARD */
app.get("/admin/invites", (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin");

  const rows = fs
    .readFileSync(INVITES_FILE, "utf8")
    .split("\n")
    .filter(Boolean)
    .map(JSON.parse)
    .reverse();

  res.render("pages/admin-invites", {
    SITE: site(),
    path: "/admin/invites",
    rows
  });
});

app.listen(PORT, () => {
  console.log(`Atmakosh site running on port ${PORT}`);
});

/* ADMIN LOGOUT */
app.get("/admin/logout", (req, res) => {
  res.setHeader(
    "Set-Cookie",
    "admin=; HttpOnly; Path=/; Max-Age=0"
  );
  res.redirect("/");
});
