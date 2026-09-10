from flask import Flask, render_template, request, jsonify, session
import joblib
import sqlite3
import secrets
from datetime import datetime
from url_features import extract_features, analyze_url

app = Flask(__name__)

app.secret_key = secrets.token_hex(32)

model = joblib.load("phishing_model.pkl")

def create_database():
    conn = sqlite3.connect("scan_history.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            url TEXT,
            result TEXT,
            confidence REAL,
            scan_time TEXT
        )
    """)

    # Add session_id if the old table already exists
    cursor.execute("PRAGMA table_info(scans)")
    columns = [column[1] for column in cursor.fetchall()]

    if "session_id" not in columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN session_id TEXT")

    conn.commit()
    conn.close()


def get_session_id():
    if "user_session" not in session:
        session["user_session"] = secrets.token_hex(16)

    return session["user_session"]


def save_scan(url, result, confidence):
    conn = sqlite3.connect("scan_history.db")
    cursor = conn.cursor()

    session_id = get_session_id()

    cursor.execute("""
        INSERT INTO scans
        (session_id, url, result, confidence, scan_time)
        VALUES (?, ?, ?, ?, ?)
    """, (
        session_id,
        url,
        result,
        confidence,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():

    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({
            "error": "Please enter a URL"
        }), 400

    features = extract_features(url)

    prediction = model.predict([features])[0]
    probabilities = model.predict_proba([features])[0]

    confidence = max(probabilities) * 100

    if prediction == 1:
        result = "Phishing"
    else:
        result = "Legitimate"

    risks = analyze_url(url)

    save_scan(url, result, confidence)

    return jsonify({
        "url": url,
        "result": result,
        "confidence": round(confidence, 2),
        "risks": risks
    })


@app.route("/history")
def history():

    conn = sqlite3.connect("scan_history.db")
    cursor = conn.cursor()

    session_id = get_session_id()

    cursor.execute("""
        SELECT url, result, confidence, scan_time
        FROM scans
        WHERE session_id = ?
        ORDER BY id DESC
        LIMIT 20
    """, (session_id,))

    rows = cursor.fetchall()
    conn.close()

    history_data = []

    for row in rows:
        history_data.append({
            "url": row[0],
            "result": row[1],
            "confidence": row[2],
            "time": row[3]
        })

    return jsonify(history_data)


create_database()

if __name__ == "__main__":
    app.run(debug=True)
