from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
from datetime import datetime, timezone
import os

app = Flask(__name__, static_folder='static')
CORS(app)

def canvas_get(domain, token, endpoint, params={}):
    results = []
    url = f"https://{domain}/api/v1{endpoint}"
    headers = {"Authorization": f"Bearer {token}"}
    while url:
        r = requests.get(url, headers=headers, params=params)
        r.raise_for_status()
        data = r.json()
        if isinstance(data, list):
            results.extend(data)
        else:
            return data
        url = r.links.get("next", {}).get("url")
        params = {}
    return results

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/api/assignments", methods=["POST"])
def get_assignments():
    body = request.json
    domain = body.get("domain", "").strip().replace("https://", "").replace("/", "")
    token = body.get("token", "").strip()

    if not domain or not token:
        return jsonify({"error": "Domain and token required"}), 400

    try:
        # Get active courses
        courses = canvas_get(domain, token, "/courses", {
            "enrollment_state": "active",
            "per_page": 50
        })
        courses = [c for c in courses if "name" in c and not c.get("access_restricted_by_date")]

        assignments = []
        now = datetime.now(timezone.utc)

        for course in courses:
            cid = course["id"]
            cname = course["name"]

            # Upcoming assignments
            try:
                upcoming = canvas_get(domain, token, f"/courses/{cid}/assignments", {
                    "per_page": 100,
                    "bucket": "future",
                    "order_by": "due_at"
                })
                for a in upcoming:
                    assignments.append(format_assignment(a, cname, now))
            except:
                pass

            # Missing/overdue
            try:
                past = canvas_get(domain, token, f"/courses/{cid}/assignments", {
                    "per_page": 100,
                    "bucket": "past",
                    "order_by": "due_at"
                })
                for a in past:
                    if a.get("is_missing_submission"):
                        if not any(x["id"] == a["id"] for x in assignments):
                            assignments.append(format_assignment(a, cname, now))
            except:
                pass

        # Sort: missing first, then by due date
        assignments.sort(key=lambda a: (
            0 if a["missing"] else 1,
            a["due_raw"] or "9999"
        ))

        return jsonify({
            "assignments": assignments,
            "course_count": len(courses)
        })

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            return jsonify({"error": "Invalid token — check your Canvas access token"}), 401
        return jsonify({"error": f"Canvas API error: {e.response.status_code}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def format_assignment(a, course_name, now):
    due_raw = a.get("due_at")
    due_str = None
    hours_until = None

    if due_raw:
        due_dt = datetime.fromisoformat(due_raw.replace("Z", "+00:00"))
        due_str = due_dt.strftime("%b %d, %I:%M %p")
        hours_until = (due_dt - now).total_seconds() / 3600

    return {
        "id": a["id"],
        "name": a["name"],
        "course": course_name,
        "due": due_str,
        "due_raw": due_raw,
        "points": a.get("points_possible"),
        "missing": a.get("is_missing_submission", False),
        "due_soon": hours_until is not None and 0 < hours_until <= 48,
        "url": a.get("html_url", "")
    }

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
