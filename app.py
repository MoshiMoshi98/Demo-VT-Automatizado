from flask import Flask, render_template, request, jsonify
import vt, os, re
from datetime import datetime, timedelta

app = Flask(__name__)
VT_API_KEY = os.environ.get("VT_API_KEY", "f2c83df5f4ce4ee2126f44d0082509efb1ff87aee930dffaf0772f08775d6458")

request_times = []

def detect_ioc_type(value):
    value = value.strip().lower()
    if re.match(r"^[a-f0-9]{64}$", value): return "sha256"
    elif re.match(r"^[a-f0-9]{32}$", value): return "md5"
    elif re.match(r"^[a-f0-9]{40}$", value): return "sha1"
    elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value): return "ip"
    elif "." in value: return "domain"
    return "unknown"

def check_rate_limit():
    global request_times
    now = datetime.now()
    cutoff = now - timedelta(minutes=1)
    request_times = [t for t in request_times if t > cutoff]
    if len(request_times) >= 4:
        return (min(request_times) + timedelta(minutes=1) - now).total_seconds()
    return 0

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan_one", methods=["POST"])
def scan_one():
    wait = check_rate_limit()
    if wait > 0:
        return jsonify({"status": "wait", "seconds": int(wait) + 1})

    data = request.get_json()
    value = data.get("ioc", "").strip().lower()
    ioc_type = detect_ioc_type(value)

    request_times.append(datetime.now())

    try:
        with vt.Client(VT_API_KEY) as client:
            if ioc_type in ["md5", "sha1", "sha256"]:
                obj = client.get_object(f"/files/{value}")
            elif ioc_type == "ip":
                obj = client.get_object(f"/ip_addresses/{value}")
            elif ioc_type == "domain":
                obj = client.get_object(f"/domains/{value}")
            else:
                return jsonify({"status": "error", "error": "Tipo no soportado"})

            stats = obj.last_analysis_stats
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())

            threat_label = ""
            threat_info = getattr(obj, "popular_threat_classification", {})
            if threat_info:
                threat_label = threat_info.get("suggested_threat_label", "")

            return jsonify({
                "status": "scanned",
                "ioc": value,
                "ioc_type": ioc_type,
                "malicious": malicious,
                "suspicious": suspicious,
                "total": total,
                "score": f"{malicious}/{total}",
                "threat_label": threat_label,
                "file_name": getattr(obj, "meaningful_name", ""),
                "file_type": getattr(obj, "type_description", ""),
                "country": getattr(obj, "country", ""),
                "as_owner": getattr(obj, "as_owner", ""),
            })

    except vt.error.APIError as e:
        if "NotFoundError" in str(e):
            return jsonify({"status": "not_found", "ioc": value, "ioc_type": ioc_type})
        return jsonify({"status": "error", "error": str(e)})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})

if __name__ == "__main__":
    app.run(debug=True)
