"""
Hybrid Incident Response Agent — Flask Backend
Run: python app.py
"""

from flask import Flask, request, jsonify, send_from_directory
import sqlite3, jwt, os, uuid
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, static_folder="static", template_folder="templates")

@app.after_request
def add_cors(r):
    r.headers['Access-Control-Allow-Origin'] = '*'
    r.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    r.headers['Access-Control-Allow-Methods'] = 'GET,POST,PATCH,DELETE,OPTIONS'
    return r

@app.before_request
def handle_options():
    from flask import request as req
    if req.method == 'OPTIONS':
        return jsonify({}), 200

SECRET_KEY = os.environ.get("JWT_SECRET", "hybrid-ir-super-secret-2024")
DB_PATH = os.environ.get("DB_PATH", "hybrid_ir.db")

# ─── DB Setup ────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'SECURITY_ANALYST',
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            affected_system TEXT NOT NULL,
            severity TEXT NOT NULL,
            reporter_name TEXT,
            response_plan TEXT,
            status TEXT DEFAULT 'OPEN',
            notes TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS risk_assessments (
            id TEXT PRIMARY KEY,
            incident_type TEXT,
            systems_affected INTEGER,
            data_sensitivity INTEGER,
            total_score INTEGER,
            severity_level TEXT,
            action_plan TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS activity_logs (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            action TEXT,
            detail TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
    """)
    db.commit()

    # Seed admin user if not exists
    cur = db.execute("SELECT id FROM users WHERE email='admin@soc.cyber'")
    if not cur.fetchone():
        hashed = generate_password_hash("admin123")
        db.execute("INSERT INTO users VALUES (?,?,?,?,?,datetime('now'))",
                   (str(uuid.uuid4()), "admin@soc.cyber", "SecOps Director", hashed, "ADMIN"))

    # Seed sample incidents
    cur = db.execute("SELECT COUNT(*) as c FROM incidents")
    if cur.fetchone()["c"] == 0:
        samples = [
            (str(uuid.uuid4()), "ransomware", "Finance DB Server", "Critical", "Alice Smith",
             "Disconnect system, preserve backups, contact CERT.", "OPEN", None),
            (str(uuid.uuid4()), "phishing", "Corporate Mail Exchange", "Medium", "Bob Jones",
             "Block sender, reset passwords, alert users.", "OPEN", None),
            (str(uuid.uuid4()), "ddos", "Public Web Portal", "High", "Charlie Root",
             "Enable traffic filtering and contact ISP.", "IN_PROGRESS", None),
            (str(uuid.uuid4()), "malware", "Workstation WS-042", "High", "Diana Prince",
             "Isolate infected device, run antivirus scan, notify admin.", "OPEN", "Detected via EDR alert"),
            (str(uuid.uuid4()), "data breach", "Customer CRM System", "Critical", "Eve Torres",
             "Revoke access, notify DPO, audit logs immediately.", "RESOLVED", "PII exposed"),
        ]
        db.executemany("INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,datetime('now'))", samples)

    db.commit()
    db.close()

# ─── Auth Helpers ─────────────────────────────────────────────────────────────

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return jsonify({"error": "Token required"}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user = data
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except Exception:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

def log_action(user_id, action, detail=""):
    try:
        db = get_db()
        db.execute("INSERT INTO activity_logs VALUES (?,?,?,?,datetime('now'))",
                   (str(uuid.uuid4()), user_id, action, detail))
        db.commit()
        db.close()
    except:
        pass

# ─── Auth Routes ──────────────────────────────────────────────────────────────

@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.json
    email = data.get("email", "").strip().lower()
    name = data.get("name", "").strip()
    password = data.get("password", "")
    role = data.get("role", "SECURITY_ANALYST")

    if not all([email, name, password]):
        return jsonify({"error": "All fields required"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    db = get_db()
    if db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
        db.close()
        return jsonify({"error": "Email already registered"}), 409

    hashed = generate_password_hash(password)
    uid = str(uuid.uuid4())
    db.execute("INSERT INTO users VALUES (?,?,?,?,?,datetime('now'))", (uid, email, name, hashed, role))
    db.commit()
    db.close()
    return jsonify({"message": "Account created successfully"}), 201

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    db.close()

    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    token = jwt.encode({
        "userId": user["id"],
        "role": user["role"],
        "name": user["name"],
        "email": user["email"],
        "exp": datetime.utcnow() + timedelta(hours=8)
    }, SECRET_KEY, algorithm="HS256")

    log_action(user["id"], "LOGIN", f"User {email} logged in")
    return jsonify({"token": token, "user": {"name": user["name"], "role": user["role"], "email": user["email"]}})

@app.route("/api/auth/forgot-password", methods=["POST"])
def forgot_password():
    email = request.json.get("email", "").strip().lower()
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    db.close()
    # In production you'd send an email; here we just acknowledge
    return jsonify({"message": "If that email exists, a reset link has been sent."})

# ─── Incidents Routes ─────────────────────────────────────────────────────────

@app.route("/api/incidents", methods=["GET"])
@token_required
def get_incidents():
    db = get_db()
    rows = db.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/incidents", methods=["POST"])
@token_required
def create_incident():
    body = request.json
    iid = str(uuid.uuid4())
    db = get_db()
    db.execute("INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,datetime('now'))", (
        iid,
        body.get("type", "unknown"),
        body.get("affected_system", ""),
        body.get("severity", "Low"),
        body.get("reporter_name", "System"),
        body.get("response_plan", ""),
        "OPEN",
        body.get("notes")
    ))
    db.commit()
    row = db.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()
    db.close()
    log_action(request.user["userId"], "CREATE_INCIDENT", f"Type: {body.get('type')}")
    return jsonify(dict(row)), 201

@app.route("/api/incidents/<iid>", methods=["DELETE"])
@token_required
def delete_incident(iid):
    db = get_db()
    db.execute("DELETE FROM incidents WHERE id=?", (iid,))
    db.commit()
    db.close()
    log_action(request.user["userId"], "DELETE_INCIDENT", f"ID: {iid}")
    return jsonify({"message": "Deleted"}), 200

@app.route("/api/incidents/<iid>", methods=["PATCH"])
@token_required
def update_incident_status(iid):
    status = request.json.get("status")
    db = get_db()
    db.execute("UPDATE incidents SET status=? WHERE id=?", (status, iid))
    db.commit()
    db.close()
    return jsonify({"message": "Updated"})

# ─── Risk Assessments Routes ──────────────────────────────────────────────────

@app.route("/api/risk-assessments", methods=["GET"])
@token_required
def get_risk():
    db = get_db()
    rows = db.execute("SELECT * FROM risk_assessments ORDER BY created_at DESC").fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/risk-assessments", methods=["POST"])
@token_required
def create_risk():
    body = request.json
    rid = str(uuid.uuid4())
    db = get_db()
    db.execute("INSERT INTO risk_assessments VALUES (?,?,?,?,?,?,?,datetime('now'))", (
        rid,
        body.get("incident_type"),
        body.get("systems_affected"),
        body.get("data_sensitivity"),
        body.get("total_score"),
        body.get("severity_level"),
        body.get("action_plan")
    ))
    db.commit()
    row = db.execute("SELECT * FROM risk_assessments WHERE id=?", (rid,)).fetchone()
    db.close()
    return jsonify(dict(row)), 201

# ─── Analytics Route ──────────────────────────────────────────────────────────

@app.route("/api/analytics", methods=["GET"])
@token_required
def get_analytics():
    db = get_db()

    # Severity counts
    sev = db.execute("""
        SELECT severity, COUNT(*) as count FROM incidents GROUP BY severity
    """).fetchall()

    # Type counts
    types = db.execute("""
        SELECT type, COUNT(*) as count FROM incidents GROUP BY type
    """).fetchall()

    # Monthly trends (last 6 months)
    monthly = db.execute("""
        SELECT strftime('%Y-%m', created_at) as month, COUNT(*) as count
        FROM incidents
        GROUP BY month ORDER BY month DESC LIMIT 6
    """).fetchall()

    # Risk score distribution
    risk_dist = db.execute("""
        SELECT severity_level, COUNT(*) as count FROM risk_assessments GROUP BY severity_level
    """).fetchall()

    db.close()
    return jsonify({
        "by_severity": [dict(r) for r in sev],
        "by_type": [dict(r) for r in types],
        "monthly": [dict(r) for r in monthly],
        "risk_distribution": [dict(r) for r in risk_dist]
    })

# ─── Activity Logs ────────────────────────────────────────────────────────────

@app.route("/api/activity-logs", methods=["GET"])
@token_required
def get_logs():
    if request.user.get("role") != "ADMIN":
        return jsonify({"error": "Admin only"}), 403
    db = get_db()
    rows = db.execute("SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 50").fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

# ─── Serve Frontend ───────────────────────────────────────────────────────────

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve(path):
    if path and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, "index.html")

# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV", "development") == "development"
    print(f"\n🛡️  Hybrid IR Agent running on http://localhost:{port}")
    print(f"   Default login: admin@soc.cyber / admin123\n")
    app.run(host="0.0.0.0", port=port, debug=debug)
