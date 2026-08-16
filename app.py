"""
SOC Dashboard Backend API Server
Handles alert generation, status changes, metric aggregation, and serving the UI.
"""

from flask import Flask, jsonify, request, send_from_directory
from rules_engine import DetectionEngine
from log_generator import generate_sample_logs
import os

app = Flask(__name__, static_folder="static")

# In-memory storage for SOC demonstration
CURRENT_LOGS = generate_sample_logs()
DETECTION_ENGINE = DetectionEngine()
ALERTS_DB = DETECTION_ENGINE.analyze_logs(CURRENT_LOGS)

@app.route("/")
def serve_dashboard():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    severity = request.args.get("severity")
    status = request.args.get("status")

    filtered = ALERTS_DB
    if severity and severity != "ALL":
        filtered = [a for a in filtered if a["severity"] == severity]
    if status and status != "ALL":
        filtered = [a for a in filtered if a["status"] == status]

    return jsonify({"alerts": filtered, "total": len(filtered)})

@app.route("/api/alerts/<alert_id>/status", methods=["PATCH"])
def update_alert_status(alert_id):
    data = request.get_json() or {}
    new_status = data.get("status")
    valid_statuses = ["New", "In Progress", "Resolved", "False Positive"]

    if new_status not in valid_statuses:
        return jsonify({"error": "Invalid status value"}), 400

    for alert in ALERTS_DB:
        if alert["id"] == alert_id:
            alert["status"] = new_status
            return jsonify({"message": "Status updated successfully", "alert": alert})

    return jsonify({"error": "Alert not found"}), 404

@app.route("/api/stats", methods=["GET"])
def get_stats():
    total = len(ALERTS_DB)
    critical = sum(1 for a in ALERTS_DB if a["severity"] == "CRITICAL")
    high = sum(1 for a in ALERTS_DB if a["severity"] == "HIGH")
    medium = sum(1 for a in ALERTS_DB if a["severity"] == "MEDIUM")
    low = sum(1 for a in ALERTS_DB if a["severity"] == "LOW")

    open_incidents = sum(1 for a in ALERTS_DB if a["status"] in ["New", "In Progress"])
    resolved = sum(1 for a in ALERTS_DB if a["status"] == "Resolved")
    false_positives = sum(1 for a in ALERTS_DB if a["status"] == "False Positive")

    category_counts = {}
    for a in ALERTS_DB:
        cat = a["category"]
        category_counts[cat] = category_counts.get(cat, 0) + 1

    return jsonify({
        "total_alerts": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "open_incidents": open_incidents,
        "resolved": resolved,
        "false_positives": false_positives,
        "categories": category_counts,
        "total_logs_processed": len(CURRENT_LOGS)
    })

@app.route("/api/logs/simulate", methods=["POST"])
def simulate_new_logs():
    global CURRENT_LOGS, ALERTS_DB
    new_logs = generate_sample_logs()
    CURRENT_LOGS.extend(new_logs)
    ALERTS_DB = DETECTION_ENGINE.analyze_logs(CURRENT_LOGS)
    return jsonify({
        "message": f"Injected {len(new_logs)} new log entries.",
        "new_alert_count": len(ALERTS_DB)
    })

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)