from flask import Flask, render_template, request, jsonify
import joblib
import sqlite3
from datetime import datetime
from url_features import extract_features, analyze_url

app = Flask(__name__)

model = joblib.load("phishing_model.pkl")


def create_database():
    conn = sqlite3.connect("scan_history.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            result TEXT,
            confidence REAL,
            scan_time TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_scan(url, result, confidence):
    conn = sqlite3.connect("scan_history.db")
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scans
        (url, result, confidence, scan_time)
        VALUES (?, ?, ?, ?)
    """, (
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

    cursor.execute("""
        SELECT url, result, confidence, scan_time
        FROM scans
        ORDER BY id DESC
        LIMIT 20
    """)

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


if __name__ == "__main__":
    create_database()
    app.run(debug=True)