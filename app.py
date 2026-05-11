import os
import secrets
import sqlite3
from datetime import datetime

from dotenv import load_dotenv
from flask import Flask, request, jsonify

load_dotenv()  # load .env file if present (local dev)

app = Flask(__name__)

APP_TOKEN = os.environ.get("APP_TOKEN")
MASTER_TOKEN = os.environ.get("MASTER_TOKEN")

if not APP_TOKEN or not MASTER_TOKEN:
    raise RuntimeError(
        "APP_TOKEN and MASTER_TOKEN must be set in environment or .env file.\n"
        "Generate tokens with: python -c 'import secrets; print(secrets.token_hex(32))'"
    )
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS licenses (
                license_key TEXT PRIMARY KEY,
                app_name TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS app_counts (
                app_name TEXT PRIMARY KEY,
                count INTEGER NOT NULL DEFAULT 0
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS run_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_name TEXT NOT NULL,
                run_date TEXT NOT NULL
            )"""
        )


# ── Licensing ────────────────────────────────────────────────────────────────

def _ensure_license(conn, license_key, app_name):
    """Register a new license on first use; return (allowed: bool, reason: str)."""
    row = conn.execute(
        "SELECT is_active FROM licenses WHERE license_key = ?", (license_key,)
    ).fetchone()

    if row is None:
        conn.execute(
            "INSERT INTO licenses (license_key, app_name) VALUES (?, ?)",
            (license_key, app_name),
        )
        return True, "registered"

    if row["is_active"]:
        return True, "ok"

    return False, "revoked"


@app.route("/api/verify-license", methods=["GET"])
def verify_license():
    license_key = request.args.get("license", "")
    app_name = request.args.get("app", "")

    if not license_key or not app_name:
        return jsonify({"allowed": False, "reason": "license and app are required"}), 400

    db = get_db()
    row = db.execute(
        "SELECT is_active FROM licenses WHERE license_key = ? AND app_name = ?",
        (license_key, app_name),
    ).fetchone()
    db.close()

    if row is None:
        return jsonify({"allowed": False, "reason": "license not found"}), 200
    if not row["is_active"]:
        return jsonify({"allowed": False, "reason": "license revoked"}), 200

    return jsonify({"allowed": True}), 200


@app.route("/api/licenses", methods=["GET"])
def list_licenses():
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {MASTER_TOKEN}":
        return jsonify({"error": "unauthorized"}), 401

    db = get_db()
    rows = db.execute(
        "SELECT license_key, app_name, is_active, created_at FROM licenses ORDER BY created_at"
    ).fetchall()
    db.close()

    return jsonify([
        {
            "license": row["license_key"],
            "app_name": row["app_name"],
            "active": bool(row["is_active"]),
            "created_at": row["created_at"],
        }
        for row in rows
    ]), 200


@app.route("/api/licenses/<license_key>", methods=["PUT"])
def update_license(license_key):
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {MASTER_TOKEN}":
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    active = data.get("active")

    if active is None:
        return jsonify({"error": "pass { \"active\": true/false }"}), 400

    db = get_db()
    cursor = db.execute(
        "UPDATE licenses SET is_active = ? WHERE license_key = ?",
        (int(active), license_key),
    )
    db.commit()
    db.close()

    if cursor.rowcount == 0:
        return jsonify({"error": "license not found"}), 404

    state = "activated" if active else "revoked"
    return jsonify({"status": "ok", "license": license_key, "state": state}), 200


# ── Record ───────────────────────────────────────────────────────────────────

@app.route("/api/record", methods=["POST"])
def record():
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {APP_TOKEN}":
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "invalid JSON"}), 400

    app_name = data.get("App name")
    license_key = data.get("License")
    run_date = data.get("Date")

    if not app_name or not license_key or not run_date:
        return jsonify({
            "error": "missing fields: 'App name', 'License', and 'Date' are required"
        }), 400

    with get_db() as conn:
        allowed, reason = _ensure_license(conn, license_key, app_name)
        if not allowed:
            return jsonify({"error": f"license {reason}"}), 403

        conn.execute(
            """INSERT INTO app_counts (app_name, count)
               VALUES (?, 1)
               ON CONFLICT(app_name) DO UPDATE SET count = count + 1""",
            (app_name,),
        )
        conn.execute(
            "INSERT INTO run_history (app_name, run_date) VALUES (?, ?)",
            (app_name, run_date),
        )

    return jsonify({"status": "ok"}), 200


# ── Stats ────────────────────────────────────────────────────────────────────

@app.route("/api/stats", methods=["GET"])
def stats():
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {MASTER_TOKEN}":
        return jsonify({"error": "unauthorized"}), 401

    db = get_db()
    counts = db.execute("SELECT app_name, count FROM app_counts ORDER BY app_name").fetchall()
    history = db.execute("SELECT app_name, run_date FROM run_history ORDER BY id").fetchall()
    db.close()

    return jsonify({
        "App count": {row["app_name"]: row["count"] for row in counts},
        "History run": [f"{row['app_name']}: {row['run_date']}" for row in history],
    }), 200


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
