// UdyamSetu backend: accounts + synced "saved schemes" and document checklist.
// Runs as a Netlify Function; data lives in Netlify Blobs (no database to set up).
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(crypto.scrypt);

const COOKIE = "us_session";
const SESSION_SECONDS = 60 * 60 * 24 * 14; // 14 days
const LOGIN_WINDOW = 15 * 60 * 1000;
const REG_WINDOW = 60 * 60 * 1000;

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const SCHEME_ID = /^[a-z0-9_-]{1,20}$/;
const DOC_KEY = /^[a-z0-9_-]{1,30}$/;

const users = () => getStore({ name: "users", consistency: "strong" });
const userData = () => getStore({ name: "userdata", consistency: "strong" });
const limits = () => getStore({ name: "limits", consistency: "strong" });

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex").slice(0, 32);

/* ---------- small helpers ---------- */
function json(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers },
  });
}

async function readJson(req) {
  const text = await req.text();
  if (text.length > 20000) return null;
  try { return JSON.parse(text); } catch { return null; }
}

function getCookie(req, name) {
  const raw = req.headers.get("cookie") || "";
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

function cookieHeader(value, maxAge, secure) {
  return `${COOKIE}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure ? "; Secure" : ""}`;
}

/* ---------- signed session token (HMAC) ---------- */
function sign(payload, secret) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const mac = crypto.createHmac("sha256", secret).update(body).digest("base64url");
  return `${body}.${mac}`;
}

function verify(token, secret) {
  if (!token) return null;
  const [body, mac] = token.split(".");
  if (!body || !mac) return null;
  const want = Buffer.from(crypto.createHmac("sha256", secret).update(body).digest("base64url"));
  const got = Buffer.from(mac);
  if (want.length !== got.length || !crypto.timingSafeEqual(want, got)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    return p && p.exp > Date.now() / 1000 ? p : null;
  } catch { return null; }
}

/* ---------- password hashing (scrypt + random salt) ---------- */
async function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  const h = await scrypt(pw, salt, 64);
  return `s1$${salt.toString("base64")}$${h.toString("base64")}`;
}

async function checkPw(pw, stored) {
  const [v, s, h] = String(stored).split("$");
  if (v !== "s1" || !s || !h) return false;
  const want = Buffer.from(h, "base64");
  const got = await scrypt(pw, Buffer.from(s, "base64"), want.length);
  return crypto.timingSafeEqual(got, want);
}

/* ---------- simple rate limiting ---------- */
async function count(key, windowMs) {
  const r = await limits().get(key, { type: "json" });
  return r && Date.now() - r.first < windowMs ? r.count : 0;
}
async function hit(key, windowMs) {
  const r = await limits().get(key, { type: "json" });
  const now = Date.now();
  const next = r && now - r.first < windowMs ? { count: r.count + 1, first: r.first } : { count: 1, first: now };
  await limits().setJSON(key, next);
}

/* ---------- validation ---------- */
function cleanData(b) {
  if (!b || !Array.isArray(b.saved) || !b.docs || typeof b.docs !== "object" || Array.isArray(b.docs)) return null;
  if (b.saved.length > 200) return null;
  const saved = [...new Set(b.saved)].filter((x) => typeof x === "string" && SCHEME_ID.test(x));
  if (saved.length > 50) return null;
  const entries = Object.entries(b.docs);
  if (entries.length > 300) return null;
  const docs = {};
  for (const [k, v] of entries) {
    if (!DOC_KEY.test(k) || !["0", "1", "2"].includes(v)) return null;
    docs[k] = v;
  }
  return { saved, docs };
}

/* ---------- handler ---------- */
export default async (req, context) => {
  const secret = process.env.SESSION_SECRET;
  const url = new URL(req.url);
  const route = url.pathname.replace(/^\/api\/?/, "").replace(/\/+$/, "");
  const secure = url.protocol === "https:" || req.headers.get("x-forwarded-proto") === "https";
  const ip = context?.ip || req.headers.get("x-nf-client-connection-ip") || "unknown";

  if (route === "health") return json(200, { ok: true, configured: !!secret && secret.length >= 32 });
  if (!secret || secret.length < 32) return json(500, { error: "server_not_configured" });

  // CSRF defence: same-origin JSON only for anything that changes data
  if (req.method !== "GET" && req.method !== "HEAD") {
    const origin = req.headers.get("origin");
    if (origin) {
      let host = null;
      try { host = new URL(origin).host; } catch {}
      if (host !== url.host) return json(403, { error: "forbidden" });
    }
    if (!(req.headers.get("content-type") || "").includes("application/json")) {
      return json(415, { error: "json_required" });
    }
  }

  const session = () => verify(getCookie(req, COOKIE), secret);
  const startSession = (id) => cookieHeader(sign({ id, exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS }, secret), SESSION_SECONDS, secure);

  try {
    /* --- register --- */
    if (route === "register" && req.method === "POST") {
      const b = await readJson(req);
      const name = String(b?.name ?? "").trim();
      const email = String(b?.email ?? "").trim().toLowerCase();
      const password = String(b?.password ?? "");
      if (!name || name.length > 60 || !EMAIL_RE.test(email) || email.length > 254 || password.length < 8 || password.length > 128) {
        return json(400, { error: "invalid" });
      }
      const regKey = `reg-${sha(ip)}`;
      if ((await count(regKey, REG_WINDOW)) >= 10) return json(429, { error: "rate" });

      const id = sha(email);
      if (await users().get(`u-${id}`, { type: "json" })) return json(409, { error: "exists" });

      await users().setJSON(`u-${id}`, { id, name, email, pw: await hashPw(password), created: new Date().toISOString() });
      await userData().setJSON(`d-${id}`, { saved: [], docs: {} });
      await hit(regKey, REG_WINDOW);
      return json(201, { user: { name, email } }, { "Set-Cookie": startSession(id) });
    }

    /* --- login --- */
    if (route === "login" && req.method === "POST") {
      const b = await readJson(req);
      const email = String(b?.email ?? "").trim().toLowerCase();
      const password = String(b?.password ?? "");
      if (!EMAIL_RE.test(email) || email.length > 254 || !password || password.length > 128) return json(400, { error: "invalid" });

      const id = sha(email);
      const kEmail = `login-${id}`;
      const kIp = `loginip-${sha(ip)}`;
      if ((await count(kEmail, LOGIN_WINDOW)) >= 8 || (await count(kIp, LOGIN_WINDOW)) >= 40) return json(429, { error: "rate" });

      const user = await users().get(`u-${id}`, { type: "json" });
      let ok = false;
      if (user) ok = await checkPw(password, user.pw);
      else await hashPw(password); // keep timing similar for unknown emails

      if (!ok) {
        await Promise.all([hit(kEmail, LOGIN_WINDOW), hit(kIp, LOGIN_WINDOW)]);
        return json(401, { error: "credentials" });
      }
      await limits().delete(kEmail);
      return json(200, { user: { name: user.name, email: user.email } }, { "Set-Cookie": startSession(id) });
    }

    /* --- logout --- */
    if (route === "logout" && req.method === "POST") {
      return json(200, { ok: true }, { "Set-Cookie": cookieHeader("", 0, secure) });
    }

    /* --- who am I --- */
    if (route === "me" && req.method === "GET") {
      const s = session();
      if (!s) return json(200, { user: null });
      const user = await users().get(`u-${s.id}`, { type: "json" });
      if (!user) return json(200, { user: null }, { "Set-Cookie": cookieHeader("", 0, secure) });
      return json(200, { user: { name: user.name, email: user.email } });
    }

    /* --- saved schemes + document checklist --- */
    if (route === "data") {
      const s = session();
      if (!s) return json(401, { error: "auth" });
      if (req.method === "GET") {
        const d = (await userData().get(`d-${s.id}`, { type: "json" })) || { saved: [], docs: {} };
        return json(200, { saved: d.saved || [], docs: d.docs || {} });
      }
      if (req.method === "PUT") {
        const clean = cleanData(await readJson(req));
        if (!clean) return json(400, { error: "invalid" });
        await userData().setJSON(`d-${s.id}`, clean);
        return json(200, { ok: true });
      }
    }

    return json(404, { error: "not_found" });
  } catch (e) {
    console.error("api error", e);
    return json(500, { error: "server_error" });
  }
};

export const config = { path: "/api/*" };
