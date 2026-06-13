import { useState, useEffect, useCallback, useRef } from "react";

// ─── Crypto Utilities ─────────────────────────────────────────────────────────

async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: enc.encode(salt), iterations: 210000, hash: "SHA-512" },
    keyMaterial, 256
  );
  return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function generateSalt() {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2, "0")).join("");
}

function generateSessionToken() {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map(b => b.toString(16).padStart(2, "0")).join("");
}

function generateTOTPSecret() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  return Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => chars[b % 32]).join("");
}

// Base32 decode for standard TOTP
function base32Decode(s) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0;
  const output = [];
  for (const c of s.toUpperCase().replace(/=+$/, "")) {
    const idx = chars.indexOf(c);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { bits -= 8; output.push((value >> bits) & 0xff); }
  }
  return new Uint8Array(output);
}

async function getTOTPCode(secret, offset = 0) {
  const counter = Math.floor(Date.now() / 1000 / 30) + offset;
  const key = await crypto.subtle.importKey(
    "raw", base32Decode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]
  );
  const buf = new ArrayBuffer(8);
  new DataView(buf).setUint32(4, counter, false);
  const sig = await crypto.subtle.sign("HMAC", key, buf);
  const arr = new Uint8Array(sig);
  const o = arr[19] & 0xf;
  const code = (
    ((arr[o] & 0x7f) << 24) | ((arr[o+1] & 0xff) << 16) |
    ((arr[o+2] & 0xff) << 8) | (arr[o+3] & 0xff)
  ) % 1000000;
  return String(code).padStart(6, "0");
}

// Verify with grace period (prev, current, next window)
async function verifyTOTP(secret, userCode) {
  for (const offset of [-1, 0, 1]) {
    const expected = await getTOTPCode(secret, offset);
    if (expected === userCode) return true;
  }
  return false;
}

// Generate 8 backup codes
function generateBackupCodes() {
  return Array.from({ length: 8 }, () =>
    Array.from(crypto.getRandomValues(new Uint8Array(4)))
      .map(b => b.toString(16).padStart(2, "0")).join("").toUpperCase()
      .match(/.{4}/g).join("-")
  );
}

// ─── QR Code Generator (pure JS, no library needed) ──────────────────────────

function buildOTPAuthURL(secret, username) {
  return `otpauth://totp/VaultAuth:${encodeURIComponent(username)}?secret=${secret}&issuer=VaultAuth&algorithm=SHA1&digits=6&period=30`;
}

// Minimal QR code using Google Charts API (reliable, widely used)
function QRCodeImage({ url, size = 180 }) {
  const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=${size}x${size}&data=${encodeURIComponent(url)}&bgcolor=0e0e1a&color=a5b4fc&margin=10`;
  return (
    <img
      src={qrUrl}
      alt="QR Code"
      width={size}
      height={size}
      style={{ borderRadius: 12, border: "1px solid #1e1e2e", display: "block" }}
      onError={e => { e.target.style.display = "none"; }}
    />
  );
}

// ─── Input Validation ─────────────────────────────────────────────────────────

function sanitize(str) {
  return str.replace(/['";\\<>]/g, "").trim();
}
function validateEmail(e) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
}
function validatePassword(pw) {
  if (pw.length < 8) return "At least 8 characters required.";
  if (!/[A-Z]/.test(pw)) return "Include at least one uppercase letter.";
  if (!/[0-9]/.test(pw)) return "Include at least one number.";
  if (!/[^A-Za-z0-9]/.test(pw)) return "Include at least one special character.";
  return null;
}

// ─── In-memory DB ─────────────────────────────────────────────────────────────

const DB = { users: {}, sessions: {} };

// ─── Password Strength ────────────────────────────────────────────────────────

function PasswordStrength({ password }) {
  const checks = [
    { label: "8+ chars", pass: password.length >= 8 },
    { label: "Uppercase", pass: /[A-Z]/.test(password) },
    { label: "Number", pass: /[0-9]/.test(password) },
    { label: "Special", pass: /[^A-Za-z0-9]/.test(password) },
  ];
  const score = checks.filter(c => c.pass).length;
  const colors = ["#ef4444", "#f97316", "#eab308", "#22c55e"];
  const labels = ["Weak", "Fair", "Good", "Strong"];
  if (!password) return null;
  return (
    <div style={{ marginTop: 6 }}>
      <div style={{ display: "flex", gap: 4, marginBottom: 4 }}>
        {[0,1,2,3].map(i => (
          <div key={i} style={{
            flex: 1, height: 3, borderRadius: 2,
            background: i < score ? colors[score-1] : "#2a2a3a",
            transition: "background 0.3s"
          }}/>
        ))}
      </div>
      <div style={{ display: "flex", justifyContent: "space-between" }}>
        <span style={{ fontSize: 11, color: colors[score-1] || "#666" }}>
          {labels[score-1] || "Very Weak"}
        </span>
        <div style={{ display: "flex", gap: 8 }}>
          {checks.map(c => (
            <span key={c.label} style={{ fontSize: 10, color: c.pass ? "#22c55e" : "#555" }}>
              {c.pass ? "✓" : "○"} {c.label}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── 2FA Setup Modal (QR + Secret + Backup Codes) ────────────────────────────

function Setup2FAModal({ secret, username, backupCodes, onClose }) {
  const [tab, setTab] = useState("qr"); // qr | backup
  const [code, setCode] = useState("------");
  const [timeLeft, setTimeLeft] = useState(30);
  const [copied, setCopied] = useState(false);
  const otpUrl = buildOTPAuthURL(secret, username);

  useEffect(() => {
    let mounted = true;
    const update = async () => {
      if (!mounted) return;
      const c = await getTOTPCode(secret);
      const tl = 30 - (Math.floor(Date.now() / 1000) % 30);
      setCode(c); setTimeLeft(tl);
    };
    update();
    const interval = setInterval(update, 1000);
    return () => { mounted = false; clearInterval(interval); };
  }, [secret]);

  const timerColor = timeLeft <= 5 ? "#ef4444" : timeLeft <= 10 ? "#f97316" : "#6366f1";

  const copySecret = () => {
    navigator.clipboard.writeText(secret);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const copyCodes = () => {
    navigator.clipboard.writeText(backupCodes.join("\n"));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={{
      position: "fixed", inset: 0, background: "rgba(0,0,0,0.85)",
      display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100,
      padding: 16
    }}>
      <div style={{
        background: "#0e0e1a", border: "1px solid #1e1e2e", borderRadius: 20,
        padding: "28px 28px 24px", maxWidth: 400, width: "100%",
        maxHeight: "90vh", overflowY: "auto"
      }}>
        {/* Header */}
        <div style={{ textAlign: "center", marginBottom: 20 }}>
          <div style={{ fontSize: 28, marginBottom: 6 }}>🛡️</div>
          <div style={{ fontSize: 17, fontWeight: 700, color: "#e2e2f0" }}>2FA Setup</div>
          <div style={{ fontSize: 12, color: "#555", marginTop: 3 }}>
            Save your QR code and backup codes before continuing
          </div>
        </div>

        {/* Tabs */}
        <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
          {["qr", "backup"].map(t => (
            <button key={t} onClick={() => setTab(t)} style={{
              flex: 1, padding: "8px", borderRadius: 8, border: "none",
              background: tab === t ? "#6366f1" : "#0a0a14",
              color: tab === t ? "#fff" : "#555",
              fontSize: 12, fontWeight: 600, cursor: "pointer",
              border: tab === t ? "none" : "1px solid #1e1e2e"
            }}>
              {t === "qr" ? "📱 QR Code" : "🔑 Backup Codes"}
            </button>
          ))}
        </div>

        {tab === "qr" && (
          <>
            {/* QR Code */}
            <div style={{ display: "flex", justifyContent: "center", marginBottom: 16 }}>
              <QRCodeImage url={otpUrl} size={180} />
            </div>
            <div style={{ fontSize: 12, color: "#555", textAlign: "center", marginBottom: 16 }}>
              Scan with <strong style={{ color: "#888" }}>Google Authenticator</strong> or <strong style={{ color: "#888" }}>Authy</strong>
            </div>

            {/* Manual secret */}
            <div style={{ fontSize: 11, color: "#555", marginBottom: 6, letterSpacing: "0.05em" }}>
              OR ENTER MANUALLY
            </div>
            <div style={{
              display: "flex", alignItems: "center", gap: 8,
              background: "#0a0a14", border: "1px solid #1e1e2e",
              borderRadius: 8, padding: "8px 12px", marginBottom: 16
            }}>
              <code style={{ flex: 1, fontSize: 12, color: "#6366f1", wordBreak: "break-all", letterSpacing: "0.1em" }}>
                {secret}
              </code>
              <button onClick={copySecret} style={{
                background: "#1a1a2e", border: "none", borderRadius: 6,
                color: copied ? "#22c55e" : "#888", fontSize: 11, padding: "4px 8px",
                cursor: "pointer", flexShrink: 0
              }}>
                {copied ? "✓ Copied" : "Copy"}
              </button>
            </div>

            {/* Live code preview */}
            <div style={{
              background: "#0a0a14", border: "1px solid #1e1e2e",
              borderRadius: 10, padding: "12px 16px"
            }}>
              <div style={{ fontSize: 11, color: "#555", marginBottom: 6, textAlign: "center" }}>
                CURRENT CODE (verify your app matches)
              </div>
              <div style={{
                fontFamily: "monospace", fontSize: 32, fontWeight: 700,
                letterSpacing: "0.3em", color: timerColor,
                textAlign: "center", transition: "color 0.3s"
              }}>
                {code}
              </div>
              <div style={{ height: 2, background: "#1a1a2e", borderRadius: 2, overflow: "hidden", marginTop: 8 }}>
                <div style={{
                  height: "100%", background: timerColor,
                  width: `${(timeLeft / 30) * 100}%`,
                  transition: "width 1s linear, background 0.3s"
                }}/>
              </div>
              <div style={{ fontSize: 10, color: "#444", textAlign: "center", marginTop: 4 }}>
                Refreshes in {timeLeft}s
              </div>
            </div>
          </>
        )}

        {tab === "backup" && (
          <>
            <div style={{
              background: "#1a0f00", border: "1px solid #3a2500",
              borderRadius: 8, padding: "10px 14px", marginBottom: 16
            }}>
              <div style={{ fontSize: 12, color: "#f97316", fontWeight: 600, marginBottom: 4 }}>
                ⚠ Save these codes now!
              </div>
              <div style={{ fontSize: 11, color: "#855" }}>
                Each code can only be used once. Store them somewhere safe — you'll need them if you lose your phone.
              </div>
            </div>

            <div style={{
              display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 16
            }}>
              {backupCodes.map((code, i) => (
                <div key={i} style={{
                  background: "#0a0a14", border: "1px solid #1e1e2e",
                  borderRadius: 8, padding: "8px 12px",
                  fontFamily: "monospace", fontSize: 13,
                  color: "#6366f1", textAlign: "center", letterSpacing: "0.05em"
                }}>
                  {code}
                </div>
              ))}
            </div>

            <button onClick={copyCodes} style={{
              width: "100%", background: "#0a0a14", border: "1px solid #1e1e2e",
              borderRadius: 8, color: copied ? "#22c55e" : "#888",
              padding: "9px", fontSize: 12, cursor: "pointer", fontWeight: 600
            }}>
              {copied ? "✓ Copied all codes!" : "📋 Copy all codes"}
            </button>
          </>
        )}

        <button onClick={onClose} style={{
          width: "100%", background: "linear-gradient(135deg, #6366f1, #8b5cf6)",
          color: "#fff", border: "none", borderRadius: 10,
          padding: "12px", fontSize: 14, fontWeight: 600,
          cursor: "pointer", marginTop: 16
        }}>
          I've saved everything → Done
        </button>
      </div>
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────

export default function SecureLoginApp() {
  const [view, setView] = useState("login");
  const [session, setSession] = useState(null);
  const [pending2FA, setPending2FA] = useState(null);
  const [form, setForm] = useState({ username: "", email: "", password: "", confirm: "", code2fa: "" });
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState(null);
  const [show2FASetup, setShow2FASetup] = useState(null);
  const [enable2FA, setEnable2FA] = useState(false);
  const [sessionTimer, setSessionTimer] = useState(600);
  const [useBackup, setUseBackup] = useState(false);

  const showToast = useCallback((msg, type = "success") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3500);
  }, []);

  useEffect(() => {
    if (!session) return;
    const interval = setInterval(() => {
      setSessionTimer(t => {
        if (t <= 1) { handleLogout(); return 0; }
        return t - 1;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [session]);

  const field = (k, v) => setForm(f => ({ ...f, [k]: v }));
  const clearErrors = () => setErrors({});

  const handleRegister = async () => {
    clearErrors();
    const errs = {};
    const uname = sanitize(form.username);
    const email = sanitize(form.email);
    if (!uname || uname.length < 3) errs.username = "Username must be 3+ characters.";
    if (!validateEmail(email)) errs.email = "Enter a valid email address.";
    const pwErr = validatePassword(form.password);
    if (pwErr) errs.password = pwErr;
    if (form.password !== form.confirm) errs.confirm = "Passwords do not match.";
    if (DB.users[uname]) errs.username = "Username already taken.";
    if (Object.keys(errs).length) { setErrors(errs); return; }

    setLoading(true);
    const salt = generateSalt();
    const hash = await hashPassword(form.password, salt);
    const secret2fa = enable2FA ? generateTOTPSecret() : null;
    const backupCodes = enable2FA ? generateBackupCodes() : [];
    const usedBackupCodes = new Set();

    DB.users[uname] = { uname, email, hash, salt, secret2fa, backupCodes, usedBackupCodes, createdAt: Date.now() };
    setLoading(false);

    if (enable2FA && secret2fa) {
      setShow2FASetup({ secret: secret2fa, username: uname, backupCodes });
    } else {
      showToast("Account created! You can now log in.");
      setView("login");
      setForm(f => ({ ...f, username: "", email: "", password: "", confirm: "" }));
    }
  };

  const handleLogin = async () => {
    clearErrors();
    const uname = sanitize(form.username);
    if (!uname) { setErrors({ username: "Username is required." }); return; }
    if (!form.password) { setErrors({ password: "Password is required." }); return; }

    setLoading(true);
    await new Promise(r => setTimeout(r, 400));
    const user = DB.users[uname];
    if (!user) {
      await new Promise(r => setTimeout(r, 200));
      setErrors({ general: "Invalid username or password." });
      setLoading(false); return;
    }
    const hash = await hashPassword(form.password, user.salt);
    if (hash !== user.hash) {
      setErrors({ general: "Invalid username or password." });
      setLoading(false); return;
    }
    setLoading(false);

    if (user.secret2fa) {
      const tempToken = generateSessionToken();
      DB.sessions[tempToken] = { uname, temp: true, exp: Date.now() + 120000 };
      setPending2FA({ uname, token: tempToken });
      setView("verify2fa");
      setForm(f => ({ ...f, code2fa: "" }));
      setUseBackup(false);
    } else {
      createSession(uname);
    }
  };

  const handleVerify2FA = async () => {
    clearErrors();
    if (!pending2FA) return;
    setLoading(true);
    const stored = DB.sessions[pending2FA.token];
    if (!stored || stored.exp < Date.now()) {
      setErrors({ general: "Session expired. Please log in again." });
      setView("login"); setPending2FA(null); setLoading(false); return;
    }
    const user = DB.users[pending2FA.uname];

    if (useBackup) {
      // Backup code verification
      const inputCode = form.code2fa.toUpperCase().replace(/[^A-F0-9\-]/g, "");
      if (user.usedBackupCodes.has(inputCode)) {
        setErrors({ code2fa: "This backup code has already been used." });
        setLoading(false); return;
      }
      if (!user.backupCodes.includes(inputCode)) {
        setErrors({ code2fa: "Invalid backup code." });
        setLoading(false); return;
      }
      user.usedBackupCodes.add(inputCode);
      const remaining = user.backupCodes.filter(c => !user.usedBackupCodes.has(c)).length;
      delete DB.sessions[pending2FA.token];
      setLoading(false);
      createSession(pending2FA.uname);
      setPending2FA(null);
      if (remaining <= 2) showToast(`⚠ Only ${remaining} backup codes left!`, "error");
    } else {
      // TOTP verification with grace period (prev/current/next window)
      const valid = await verifyTOTP(user.secret2fa, form.code2fa);
      if (!valid) {
        setErrors({ code2fa: "Invalid code. Try the current code shown in your app." });
        setLoading(false); return;
      }
      delete DB.sessions[pending2FA.token];
      setLoading(false);
      createSession(pending2FA.uname);
      setPending2FA(null);
    }
  };

  const createSession = (uname) => {
    const token = generateSessionToken();
    const user = DB.users[uname];
    DB.sessions[token] = { uname, exp: Date.now() + 600000 };
    setSession({ token, uname, email: user.email, has2fa: !!user.secret2fa });
    setSessionTimer(600);
    setView("dashboard");
    setForm({ username: "", email: "", password: "", confirm: "", code2fa: "" });
    showToast(`Welcome back, ${uname}! 🎉`);
  };

  const handleLogout = () => {
    if (session) delete DB.sessions[session.token];
    setSession(null);
    setView("login");
    showToast("Logged out successfully.", "info");
  };

  const fmtTime = s => `${Math.floor(s/60)}:${String(s%60).padStart(2,"0")}`;

  // ── Styles ───────────────────────────────────────────────────────────────────

  const s = {
    wrap: {
      minHeight: "100vh", background: "#070710",
      display: "flex", alignItems: "center", justifyContent: "center",
      fontFamily: "'Inter', system-ui, sans-serif", color: "#e2e2f0", padding: "20px"
    },
    card: {
      background: "#0e0e1a", border: "1px solid #1a1a2e", borderRadius: 20,
      padding: "40px 40px 36px", width: "100%", maxWidth: 400,
      boxShadow: "0 0 0 1px #1a1a2e, 0 24px 64px rgba(0,0,0,0.6)"
    },
    logo: { display: "flex", alignItems: "center", gap: 10, marginBottom: 28 },
    logoIcon: {
      width: 36, height: 36, background: "linear-gradient(135deg, #6366f1, #8b5cf6)",
      borderRadius: 10, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18
    },
    logoText: { fontSize: 16, fontWeight: 700, letterSpacing: "-0.02em" },
    h2: { fontSize: 22, fontWeight: 700, marginBottom: 4, letterSpacing: "-0.02em" },
    sub: { fontSize: 13, color: "#666", marginBottom: 28 },
    label: { display: "block", fontSize: 12, color: "#888", marginBottom: 5, letterSpacing: "0.04em" },
    input: {
      width: "100%", boxSizing: "border-box",
      background: "#0a0a14", border: "1px solid #1e1e2e",
      borderRadius: 10, padding: "11px 14px", color: "#e2e2f0",
      fontSize: 14, outline: "none", transition: "border-color 0.2s"
    },
    errMsg: { fontSize: 11, color: "#ef4444", marginTop: 4 },
    group: { marginBottom: 18 },
    btn: {
      width: "100%", background: "linear-gradient(135deg, #6366f1, #8b5cf6)",
      color: "#fff", border: "none", borderRadius: 10,
      padding: "12px 0", fontSize: 14, fontWeight: 600,
      cursor: "pointer", marginTop: 4, letterSpacing: "0.02em", transition: "opacity 0.2s"
    },
    btnSecondary: { background: "transparent", border: "1px solid #1e1e2e", color: "#888" },
    link: { color: "#6366f1", cursor: "pointer", fontSize: 13 },
    divider: {
      textAlign: "center", color: "#333", fontSize: 12,
      margin: "20px 0", display: "flex", alignItems: "center", gap: 10
    },
    divLine: { flex: 1, height: 1, background: "#1a1a2e" },
    generalErr: {
      background: "#1a0a0a", border: "1px solid #3a1010",
      borderRadius: 8, padding: "10px 14px", fontSize: 12, color: "#ef4444", marginBottom: 16
    },
    badge: {
      display: "inline-flex", alignItems: "center", gap: 5,
      fontSize: 11, fontWeight: 600, letterSpacing: "0.05em", padding: "3px 8px", borderRadius: 20
    },
    toggle: {
      display: "flex", alignItems: "center", gap: 10,
      cursor: "pointer", userSelect: "none", marginBottom: 18
    }
  };

  const inputStyle = (k) => ({ ...s.input, ...(errors[k] ? { borderColor: "#ef4444" } : {}) });

  // ── Views ────────────────────────────────────────────────────────────────────

  const LoginView = () => (
    <>
      <div style={s.logo}>
        <div style={s.logoIcon}>🔐</div>
        <span style={s.logoText}>VaultAuth</span>
      </div>
      <h2 style={s.h2}>Sign in</h2>
      <p style={s.sub}>Secured with PBKDF2-SHA512 + session tokens</p>
      {errors.general && <div style={s.generalErr}>⚠ {errors.general}</div>}
      <div style={s.group}>
        <label style={s.label}>USERNAME</label>
        <input style={inputStyle("username")} value={form.username}
          onChange={e => field("username", e.target.value)}
          onKeyDown={e => e.key === "Enter" && handleLogin()}
          autoComplete="username" spellCheck={false} />
        {errors.username && <div style={s.errMsg}>{errors.username}</div>}
      </div>
      <div style={s.group}>
        <label style={s.label}>PASSWORD</label>
        <input style={inputStyle("password")} type="password" value={form.password}
          onChange={e => field("password", e.target.value)}
          onKeyDown={e => e.key === "Enter" && handleLogin()}
          autoComplete="current-password" />
        {errors.password && <div style={s.errMsg}>{errors.password}</div>}
      </div>
      <button style={{ ...s.btn, opacity: loading ? 0.7 : 1 }} onClick={handleLogin} disabled={loading}>
        {loading ? "Verifying…" : "Sign in →"}
      </button>
      <div style={s.divider}><div style={s.divLine}/><span>or</span><div style={s.divLine}/></div>
      <div style={{ textAlign: "center", fontSize: 13, color: "#555" }}>
        Don't have an account?{" "}
        <span style={s.link} onClick={() => { setView("register"); clearErrors(); }}>Create one</span>
      </div>
    </>
  );

  const RegisterView = () => (
    <>
      <div style={s.logo}>
        <div style={s.logoIcon}>🔐</div>
        <span style={s.logoText}>VaultAuth</span>
      </div>
      <h2 style={s.h2}>Create account</h2>
      <p style={s.sub}>All passwords hashed with 210,000 PBKDF2 iterations</p>
      {errors.general && <div style={s.generalErr}>⚠ {errors.general}</div>}
      <div style={s.group}>
        <label style={s.label}>USERNAME</label>
        <input style={inputStyle("username")} value={form.username}
          onChange={e => field("username", e.target.value)} autoComplete="username" spellCheck={false} />
        {errors.username && <div style={s.errMsg}>{errors.username}</div>}
      </div>
      <div style={s.group}>
        <label style={s.label}>EMAIL</label>
        <input style={inputStyle("email")} value={form.email}
          onChange={e => field("email", e.target.value)} type="email" autoComplete="email" />
        {errors.email && <div style={s.errMsg}>{errors.email}</div>}
      </div>
      <div style={s.group}>
        <label style={s.label}>PASSWORD</label>
        <input style={inputStyle("password")} type="password" value={form.password}
          onChange={e => field("password", e.target.value)} autoComplete="new-password" />
        <PasswordStrength password={form.password} />
        {errors.password && <div style={s.errMsg}>{errors.password}</div>}
      </div>
      <div style={s.group}>
        <label style={s.label}>CONFIRM PASSWORD</label>
        <input style={inputStyle("confirm")} type="password" value={form.confirm}
          onChange={e => field("confirm", e.target.value)} autoComplete="new-password" />
        {errors.confirm && <div style={s.errMsg}>{errors.confirm}</div>}
      </div>
      <label style={s.toggle} onClick={() => setEnable2FA(v => !v)}>
        <div style={{
          width: 36, height: 20, borderRadius: 10,
          background: enable2FA ? "#6366f1" : "#1e1e2e",
          position: "relative", transition: "background 0.2s", flexShrink: 0
        }}>
          <div style={{
            position: "absolute", top: 3, left: enable2FA ? 18 : 2,
            width: 14, height: 14, borderRadius: "50%",
            background: "#fff", transition: "left 0.2s"
          }}/>
        </div>
        <span style={{ fontSize: 13, color: "#888" }}>Enable Two-Factor Authentication (2FA)</span>
      </label>
      <button style={{ ...s.btn, opacity: loading ? 0.7 : 1 }} onClick={handleRegister} disabled={loading}>
        {loading ? "Creating account…" : "Create account →"}
      </button>
      <div style={{ ...s.divider, marginTop: 18 }}>
        <div style={s.divLine}/><span>or</span><div style={s.divLine}/>
      </div>
      <div style={{ textAlign: "center", fontSize: 13, color: "#555" }}>
        Already have an account?{" "}
        <span style={s.link} onClick={() => { setView("login"); clearErrors(); }}>Sign in</span>
      </div>
    </>
  );

  const Verify2FAView = () => (
    <>
      <div style={s.logo}>
        <div style={s.logoIcon}>🔐</div>
        <span style={s.logoText}>VaultAuth</span>
      </div>
      <h2 style={s.h2}>{useBackup ? "Backup Code" : "Two-Factor"} Verify</h2>
      <p style={s.sub}>
        {useBackup
          ? "Enter one of your 8-character backup codes"
          : "Enter the 6-digit code from Google Authenticator"}
      </p>
      {errors.general && <div style={s.generalErr}>⚠ {errors.general}</div>}

      <div style={s.group}>
        <label style={s.label}>{useBackup ? "BACKUP CODE" : "AUTHENTICATOR CODE"}</label>
        <input
          style={{
            ...inputStyle("code2fa"),
            fontSize: useBackup ? 18 : 28, fontFamily: "monospace",
            textAlign: "center", letterSpacing: useBackup ? "0.15em" : "0.4em", padding: "14px"
          }}
          value={form.code2fa} maxLength={useBackup ? 9 : 6}
          onChange={e => field("code2fa", useBackup
            ? e.target.value.toUpperCase()
            : e.target.value.replace(/\D/g, "")
          )}
          onKeyDown={e => e.key === "Enter" && handleVerify2FA()}
          placeholder={useBackup ? "ABCD-1234" : "000000"}
          autoComplete="one-time-code"
        />
        {errors.code2fa && <div style={s.errMsg}>{errors.code2fa}</div>}
      </div>

      {!useBackup && (
        <div style={{
          background: "#0a0a14", border: "1px solid #1a1a2e",
          borderRadius: 8, padding: "8px 12px", marginBottom: 16,
          fontSize: 11, color: "#555", textAlign: "center"
        }}>
          ✓ Accepts codes from the previous, current, and next 30s window
        </div>
      )}

      <button style={{ ...s.btn, opacity: loading ? 0.7 : 1 }} onClick={handleVerify2FA} disabled={loading}>
        {loading ? "Verifying…" : "Verify & Sign in →"}
      </button>

      <div style={{ textAlign: "center", marginTop: 14, display: "flex", justifyContent: "center", gap: 20 }}>
        <span style={{ ...s.link, color: "#555" }}
          onClick={() => { setUseBackup(v => !v); clearErrors(); field("code2fa", ""); }}>
          {useBackup ? "← Use authenticator app" : "Use backup code instead"}
        </span>
      </div>
      <div style={{ textAlign: "center", marginTop: 10 }}>
        <span style={{ ...s.link, color: "#444", fontSize: 12 }}
          onClick={() => { setView("login"); setPending2FA(null); clearErrors(); }}>
          ← Back to login
        </span>
      </div>
    </>
  );

  const DashboardView = () => {
    const sessionPct = (sessionTimer / 600) * 100;
    const timerColor = sessionTimer < 60 ? "#ef4444" : sessionTimer < 180 ? "#f97316" : "#22c55e";
    const user = session ? DB.users[session.uname] : null;
    const backupRemaining = user?.backupCodes
      ? user.backupCodes.filter(c => !user.usedBackupCodes.has(c)).length
      : 0;

    return (
      <>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
          <div style={s.logo}>
            <div style={s.logoIcon}>🔐</div>
            <span style={s.logoText}>VaultAuth</span>
          </div>
          <button style={{ ...s.btn, ...s.btnSecondary, width: "auto", padding: "7px 14px", marginTop: 0, fontSize: 12 }}
            onClick={handleLogout}>Sign out</button>
        </div>

        <div style={{
          background: "linear-gradient(135deg, #0d0d1f, #12122a)",
          border: "1px solid #1e1e2e", borderRadius: 14, padding: "18px 20px", marginBottom: 14
        }}>
          <div style={{ fontSize: 12, color: "#555", marginBottom: 4, letterSpacing: "0.05em" }}>SIGNED IN AS</div>
          <div style={{ fontSize: 20, fontWeight: 700, letterSpacing: "-0.02em", marginBottom: 3 }}>{session?.uname}</div>
          <div style={{ fontSize: 13, color: "#555" }}>{session?.email}</div>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 14 }}>
          {[
            { label: "Password Hash", value: "PBKDF2-SHA512", icon: "🔑" },
            { label: "Iterations", value: "210,000", icon: "⚙️" },
            { label: "Salt", value: "128-bit random", icon: "🧂" },
            { label: "Session Token", value: "256-bit CSPRNG", icon: "🎲" },
          ].map(item => (
            <div key={item.label} style={{
              background: "#0a0a14", border: "1px solid #1a1a2e", borderRadius: 10, padding: "12px"
            }}>
              <div style={{ fontSize: 16, marginBottom: 3 }}>{item.icon}</div>
              <div style={{ fontSize: 10, color: "#555", marginBottom: 2 }}>{item.label}</div>
              <div style={{ fontSize: 11, fontWeight: 600, color: "#888" }}>{item.value}</div>
            </div>
          ))}
        </div>

        {/* Session timer */}
        <div style={{
          background: "#0a0a14", border: "1px solid #1a1a2e",
          borderRadius: 10, padding: "12px 16px", marginBottom: 10
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
            <span style={{ fontSize: 12, color: "#888" }}>Session expires in</span>
            <span style={{ fontFamily: "monospace", fontSize: 13, color: timerColor, fontWeight: 600 }}>
              {fmtTime(sessionTimer)}
            </span>
          </div>
          <div style={{ height: 3, background: "#1a1a2e", borderRadius: 2, overflow: "hidden" }}>
            <div style={{
              height: "100%", background: timerColor, borderRadius: 2,
              width: `${sessionPct}%`, transition: "width 1s linear, background 0.3s"
            }}/>
          </div>
        </div>

        {/* 2FA status */}
        <div style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          background: "#0a0a14", border: "1px solid #1a1a2e",
          borderRadius: 10, padding: "12px 16px", marginBottom: session?.has2fa ? 10 : 0
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 16 }}>🛡️</span>
            <div>
              <div style={{ fontSize: 12, fontWeight: 600 }}>Two-Factor Auth</div>
              <div style={{ fontSize: 11, color: "#555" }}>{session?.has2fa ? "Google Authenticator" : "Not enabled"}</div>
            </div>
          </div>
          <span style={{
            ...s.badge,
            background: session?.has2fa ? "#0d1f0d" : "#1a1a0a",
            color: session?.has2fa ? "#22c55e" : "#888",
            border: `1px solid ${session?.has2fa ? "#1a3a1a" : "#2a2a1a"}`
          }}>
            {session?.has2fa ? "✓ ACTIVE" : "○ OFF"}
          </span>
        </div>

        {/* Backup codes remaining */}
        {session?.has2fa && (
          <div style={{
            display: "flex", alignItems: "center", justifyContent: "space-between",
            background: "#0a0a14", border: `1px solid ${backupRemaining <= 2 ? "#3a2500" : "#1a1a2e"}`,
            borderRadius: 10, padding: "12px 16px"
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: 16 }}>🔑</span>
              <div>
                <div style={{ fontSize: 12, fontWeight: 600 }}>Backup Codes</div>
                <div style={{ fontSize: 11, color: "#555" }}>One-time emergency access</div>
              </div>
            </div>
            <span style={{
              ...s.badge,
              background: backupRemaining <= 2 ? "#1a0f00" : "#0a0a14",
              color: backupRemaining <= 2 ? "#f97316" : "#888",
              border: `1px solid ${backupRemaining <= 2 ? "#3a2500" : "#1e1e2e"}`
            }}>
              {backupRemaining}/8 left
            </span>
          </div>
        )}
      </>
    );
  };

  return (
    <div style={s.wrap}>
      <div style={s.card}>
        {view === "login" && <LoginView />}
        {view === "register" && <RegisterView />}
        {view === "verify2fa" && <Verify2FAView />}
        {view === "dashboard" && <DashboardView />}
      </div>

      {toast && (
        <div style={{
          position: "fixed", bottom: 28, left: "50%", transform: "translateX(-50%)",
          background: toast.type === "success" ? "#0d1f0d" : toast.type === "info" ? "#0a0a1f" : "#1a0a0a",
          border: `1px solid ${toast.type === "success" ? "#1a3a1a" : toast.type === "info" ? "#1a1a3a" : "#3a1a1a"}`,
          color: toast.type === "success" ? "#22c55e" : toast.type === "info" ? "#6366f1" : "#ef4444",
          borderRadius: 10, padding: "11px 20px", fontSize: 13, fontWeight: 500,
          boxShadow: "0 8px 32px rgba(0,0,0,0.5)", zIndex: 200,
          whiteSpace: "nowrap", animation: "fadeIn 0.2s ease"
        }}>
          {toast.msg}
        </div>
      )}

      {show2FASetup && (
        <Setup2FAModal
          secret={show2FASetup.secret}
          username={show2FASetup.username}
          backupCodes={show2FASetup.backupCodes}
          onClose={() => {
            setShow2FASetup(null);
            showToast("Account created with 2FA enabled! 🛡️");
            setView("login");
            setForm(f => ({ ...f, username: "", email: "", password: "", confirm: "" }));
          }}
        />
      )}

      <style>{`
        @keyframes fadeIn { from { opacity:0; transform:translateX(-50%) translateY(6px); } to { opacity:1; transform:translateX(-50%) translateY(0); } }
        input:focus { border-color: #6366f1 !important; }
        button:hover:not(:disabled) { opacity: 0.88; }
        ::-webkit-scrollbar { width: 4px; } ::-webkit-scrollbar-track { background: #0a0a14; } ::-webkit-scrollbar-thumb { background: #1e1e2e; border-radius: 2px; }
      `}</style>
    </div>
  );
}
