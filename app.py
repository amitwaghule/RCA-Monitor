
from flask import Flask, render_template, jsonify
import psutil
import shutil
import time
import sqlite3
from pathlib import Path

app = Flask(__name__)

DB_PATH = Path(__file__).with_name("rca_history.db")


# -------------------------
# DATABASE
# -------------------------
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checked_at TEXT NOT NULL,
                cpu REAL,
                ram REAL,
                disk REAL,
                findings TEXT NOT NULL
            )
        """)


# -------------------------
# HOME
# -------------------------
@app.route("/")
def home():
    return render_template("index.html")


# -------------------------
# SYSTEM HEALTH
# -------------------------
def get_system_health():
    cpu = psutil.cpu_percent(interval=0.2)
    ram = psutil.virtual_memory()
    disk = shutil.disk_usage("C:\\")

    return {
        "cpu": cpu,
        "ram": ram.percent,
        "ram_used_gb": round(ram.used / (1024 ** 3), 2),
        "ram_total_gb": round(ram.total / (1024 ** 3), 2),
        "disk": round(disk.used / disk.total * 100, 1),
        "disk_free_gb": round(disk.free / (1024 ** 3), 2)
    }


# -------------------------
# PROCESS ANALYZER
# -------------------------
def get_top_processes():
    processes = []

    for proc in psutil.process_iter():
        try:
            proc.cpu_percent(None)
            processes.append(proc)
        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

    time.sleep(0.5)

    cpu_list = []
    ram_list = []

    for proc in processes:
        try:
            cpu = proc.cpu_percent(None)
            memory = proc.memory_info().rss / (1024 ** 2)

            info = {
                "name": proc.name() or "Unknown",
                "pid": proc.pid,
                "cpu": round(cpu, 1),
                "ram_mb": round(memory, 1)
            }

            cpu_list.append(info)
            ram_list.append(info.copy())

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

    cpu_list.sort(key=lambda x: x["cpu"], reverse=True)
    ram_list.sort(key=lambda x: x["ram_mb"], reverse=True)

    return cpu_list[:5], ram_list[:5]


# -------------------------
# HEALTH API
# -------------------------
@app.route("/api/health")
def health():
    data = get_system_health()
    alerts = []

    if data["cpu"] >= 85:
        alerts.append("High CPU usage detected")

    if data["ram"] >= 85:
        alerts.append("High RAM usage detected")

    if data["disk"] >= 90:
        alerts.append("Low disk space warning")

    if not alerts:
        alerts.append("No threshold alerts detected")

    data["alerts"] = alerts
    data["updated_at"] = time.strftime("%H:%M:%S")

    return jsonify(data)


# -------------------------
# PROCESS API
# -------------------------
@app.route("/api/processes")
def processes():
    top_cpu, top_ram = get_top_processes()

    return jsonify({
        "top_cpu": top_cpu,
        "top_ram": top_ram
    })


# -------------------------
# RCA RULE ENGINE
# -------------------------
def analyze_system(data, top_cpu, top_ram):
    findings = []

    # CPU
    if data["cpu"] >= 85:
        candidates = [p for p in top_cpu if p["cpu"] >= 20]

        if candidates:
            p = candidates[0]
            findings.append({
                "issue": "High CPU Utilization",
                "cause": "Possible resource-heavy process",
                "evidence": (
                    f"System CPU: {data['cpu']}%. "
                    f"{p['name']} PID {p['pid']} "
                    f"sampled at {p['cpu']}%."
                ),
                "action": (
                    "Check whether the application is "
                    "expected to use high CPU. Monitor again."
                ),
                "assessment": "Possible cause"
            })
        else:
            findings.append({
                "issue": "High CPU Utilization",
                "cause": "Cause not identified",
                "evidence": f"System CPU: {data['cpu']}%.",
                "action": "Repeat monitoring and inspect processes.",
                "assessment": "Insufficient evidence"
            })

    # RAM
    if data["ram"] >= 85:
        candidates = [p for p in top_ram if p["ram_mb"] >= 500]

        if candidates:
            p = candidates[0]
            findings.append({
                "issue": "High RAM Utilization",
                "cause": "Possible memory-heavy process",
                "evidence": (
                    f"System RAM: {data['ram']}%. "
                    f"{p['name']} PID {p['pid']} "
                    f"uses {p['ram_mb']} MB."
                ),
                "action": (
                    "Check application memory usage and "
                    "whether it is expected."
                ),
                "assessment": "Possible cause"
            })
        else:
            findings.append({
                "issue": "High RAM Utilization",
                "cause": "Cause not identified",
                "evidence": f"System RAM: {data['ram']}%.",
                "action": "Review memory usage over time.",
                "assessment": "Insufficient evidence"
            })

    # DISK
    if data["disk"] >= 90:
        findings.append({
            "issue": "Low Disk Space",
            "cause": "System drive nearly full",
            "evidence": (
                f"C: usage {data['disk']}%. "
                f"Free space {data['disk_free_gb']} GB."
            ),
            "action": (
                "Review Windows Storage settings. "
                "Remove only files you recognize."
            ),
            "assessment": "Threshold finding"
        })

    if not findings:
        findings.append({
            "issue": "No Configured Threshold Crossed",
            "cause": "No issue identified by current rules",
            "evidence": (
                f"CPU {data['cpu']}%, RAM {data['ram']}%, "
                f"Disk {data['disk']}%."
            ),
            "action": "Continue monitoring.",
            "assessment": "Limited assessment"
        })

    return findings


# -------------------------
# RCA + SAVE INCIDENT
# -------------------------
@app.route("/api/diagnosis", methods=["GET"])
def diagnosis():
    data = get_system_health()
    top_cpu, top_ram = get_top_processes()

    findings = analyze_system(data, top_cpu, top_ram)

    checked_at = time.strftime("%Y-%m-%d %H:%M:%S")

    # Save this analysis in SQLite
    import json

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute("""
            INSERT INTO incidents
            (checked_at, cpu, ram, disk, findings)
            VALUES (?, ?, ?, ?, ?)
        """, (
            checked_at,
            data["cpu"],
            data["ram"],
            data["disk"],
            json.dumps(findings)
        ))

        incident_id = cursor.lastrowid

    return jsonify({
        "id": incident_id,
        "findings": findings,
        "checked_at": checked_at
    })


# -------------------------
# INCIDENT HISTORY API
# -------------------------
@app.route("/api/history")
def history():
    import json

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        rows = conn.execute("""
            SELECT id, checked_at, cpu, ram, disk, findings
            FROM incidents
            ORDER BY id DESC
            LIMIT 50
        """).fetchall()

    records = []

    for row in rows:
        records.append({
            "id": row["id"],
            "checked_at": row["checked_at"],
            "cpu": row["cpu"],
            "ram": row["ram"],
            "disk": row["disk"],
            "findings": json.loads(row["findings"])
        })

    return jsonify({"history": records})


# -------------------------
# START
# -------------------------
init_db()

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
