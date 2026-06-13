# 🔐 VaultAuth — Secure Login System

A modern, secure authentication system built with React and Vite. Features industry-standard password hashing, session management, and Two-Factor Authentication (2FA) with Google Authenticator support.

---

## 🚀 Live Demo

> Run locally at `http://localhost:5173`

---

## ✨ Features

### 🔑 Authentication
- User **registration and login**
- Passwords hashed with **PBKDF2-SHA512** (210,000 iterations)
- **128-bit random salt** per user
- **256-bit CSPRNG session tokens**
- Protection against **SQL injection** via input sanitization
- **Timing attack** prevention on failed logins

### 🛡️ Two-Factor Authentication (2FA)
- **QR Code** scannable with Google Authenticator or Authy
- **TOTP** (Time-based One-Time Password) — RFC 6238 standard
- **Grace period** — accepts previous, current, and next 30s window
- **8 one-time backup codes** for emergency access
- Backup code usage tracking with low-code warnings

### 🔒 Session Management
- **10-minute session timer** with live countdown
- **Auto logout** when session expires
- Manual **Sign out** option

### ✅ Input Validation
- Real-time **password strength meter**
- Email format validation
- Username length validation
- Password requirements: 8+ chars, uppercase, number, special character

---

## 🛠️ Tech Stack

| Technology | Purpose |
|------------|---------|
| React 18 | UI Framework |
| Vite | Build Tool |
| Web Crypto API | Password hashing & TOTP |
| PBKDF2-SHA512 | Password hashing algorithm |
| TOTP (RFC 6238) | Two-Factor Authentication |

---

## 📦 Installation

### Prerequisites
- Node.js v18+ — [nodejs.org](https://nodejs.org)
- Git — [git-scm.com](https://git-scm.com)

### Steps

**1. Clone the repository**
```bash
git clone https://github.com/somashekaraTR/vaultauth.git
cd vaultauth
```

**2. Install dependencies**
```bash
npm install
```

**3. Start the development server**
```bash
npm run dev
```

**4. Open in browser**
```
http://localhost:5173
```

---

## 📱 How to Use

### Register
1. Click **"Create one"** on the login page
2. Fill in username, email, and a strong password
3. Optionally enable **Two-Factor Authentication**
4. If 2FA enabled — scan the QR code with Google Authenticator
5. Save your **backup codes** safely

### Login
1. Enter your username and password
2. If 2FA is enabled — enter the 6-digit code from Google Authenticator
3. Or use a **backup code** if you lost your phone

### Dashboard
- View your security configuration
- Monitor session expiry countdown
- Check remaining backup codes

---

## 🔐 Security Details

```
Password Hashing  : PBKDF2-SHA512
Iterations        : 210,000 (OWASP recommended)
Salt              : 128-bit cryptographically random
Session Token     : 256-bit CSPRNG
2FA Algorithm     : HMAC-SHA1 (RFC 6238)
2FA Window        : 30 seconds with ±1 grace period
Backup Codes      : 8 one-time codes (32-bit random each)
```

---

## 📁 Project Structure

```
vaultauth/
├── public/
├── src/
│   ├── App.jsx        # Main application (all components)
│   └── index.css      # Global styles (minimal)
├── index.html
├── package.json
├── vite.config.js
└── README.md
```

---

## 🚧 Production Notes

This is a frontend demo. For a production app, you would add:

- [ ] Backend server (Node.js / Python / etc.)
- [ ] Real database (PostgreSQL / MongoDB)
- [ ] HTTPS enforcement
- [ ] Rate limiting & account lockout
- [ ] Server-side session storage
- [ ] Email verification on registration

---

## 👨‍💻 Author

**Somashekara T R**
- GitHub: [@somashekaraTR](https://github.com/somashekaraTR)

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).
