# 🛡️ Hybrid IR Agent — SOC Platform

A full-stack cybersecurity Incident Response web application with Python (Flask) backend and HTML/CSS/JS frontend.

---

## 📁 Project Structure

```
hybrid-ir-agent/
├── app.py              ← Flask backend (all API routes)
├── requirements.txt    ← Python dependencies
├── render.yaml         ← Render deployment config
├── static/
│   └── index.html      ← Complete frontend (HTML + CSS + JS)
└── README.md
```

---

## 🚀 Local Setup (VS Code)

### 1. Create & activate a virtual environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the app

```bash
python app.py
```

Open **http://localhost:5000** in your browser.

### Default credentials
- **Email:** `admin@soc.cyber`
- **Password:** `admin123`

---

## 🌐 Render Deployment

### Option A — Using render.yaml (recommended)

1. Push this folder to a GitHub repository
2. Go to [render.com](https://render.com) → **New → Blueprint**
3. Connect your GitHub repo — Render reads `render.yaml` automatically
4. Click **Apply** — your app deploys with persistent storage

### Option B — Manual Web Service

1. Push to GitHub
2. Render → **New → Web Service** → connect repo
3. Configure:
   - **Runtime:** Python 3
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2`
4. **Environment Variables:**
   | Key | Value |
   |-----|-------|
   | `JWT_SECRET` | any random long string |
   | `DB_PATH` | `/var/data/hybrid_ir.db` |
   | `FLASK_ENV` | `production` |
5. **Disk** (for persistent SQLite):
   - Mount path: `/var/data`
   - Size: 1 GB

---

## ✨ Features

| Module | Description |
|--------|-------------|
| **Dashboard** | Live stats — total, critical, high, open incidents + chart |
| **Incident Lookup** | Enter any vector → auto severity + response plan |
| **Report Generator** | NIST-style dockets with print/PDF/txt download |
| **Incident Registry** | Full CRUD table with search, filter, CSV export |
| **Risk Calculator** | Quantitative scoring with visual meter |
| **Analytics** | 4 charts: severity, type, monthly trends, risk dist. |
| **Auth** | Login, register, forgot password, JWT sessions, role-based |

---

## 🔧 Tech Stack

- **Backend:** Python 3 + Flask + SQLite (via stdlib `sqlite3`)
- **Auth:** bcrypt + JWT (PyJWT)
- **Frontend:** Vanilla HTML5 + CSS3 + JavaScript (no build step)
- **Charts:** Chart.js (CDN)
- **Deploy:** Gunicorn + Render

---

## 🔐 Security Notes

- JWT tokens expire after 8 hours
- Passwords hashed with bcrypt (cost 10)
- All API routes (except auth) require valid Bearer token
- Change `JWT_SECRET` to a strong random value in production
