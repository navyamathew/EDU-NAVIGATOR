import os
import requests
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, auth, firestore
from dotenv import load_dotenv

# ==============================
# LOAD ENV
# ==============================
load_dotenv()

app = Flask(__name__)
CORS(app)

# ==============================
# FIREBASE INIT
# ==============================
if not firebase_admin._apps:
    cred = credentials.Certificate("firebase_config.json")
    firebase_admin.initialize_app(cred)

db = firestore.client()
FIREBASE_API_KEY = os.getenv("FIREBASE_API_KEY")

# ==============================
# TOKEN VERIFY
# ==============================
def verify_user():
    id_token = request.headers.get("Authorization")

    if not id_token:
        return None, ("Missing token", 401)

    try:
        decoded = auth.verify_id_token(id_token)
        return decoded["uid"], None
    except:
        return None, ("Invalid token", 401)

# ==============================
# LOGIN
# ==============================
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"

    payload = {
        "email": data.get("email"),
        "password": data.get("password"),
        "returnSecureToken": True
    }

    res = requests.post(url, json=payload)
    result = res.json()

    if "error" in result:
        return jsonify({"error": result["error"]["message"]}), 401

    return jsonify(result)

# ==============================
# GOOGLE LOGIN
# ==============================
@app.route("/google-login", methods=["POST"])
def google_login():
    data = request.get_json()
    id_token = data.get("idToken")

    try:
        decoded = auth.verify_id_token(id_token)
        return jsonify({"uid": decoded["uid"]})
    except:
        return jsonify({"error": "Invalid token"}), 401

# ==============================
# DASHBOARD
# ==============================
@app.route("/dashboard")
def dashboard():
    uid, err = verify_user()
    if err:
        return jsonify({"error": err[0]}), err[1]

    return jsonify({"message": "Welcome", "uid": uid})

# ==============================
# NOTIFICATIONS
# ==============================
@app.route("/notifications", methods=["GET"])
def get_notifications():
    uid, err = verify_user()
    if err:
        return jsonify({"error": err[0]}), err[1]

    docs = db.collection("users").document(uid).collection("notifications").stream()

    data = []
    for doc in docs:
        d = doc.to_dict()
        d["id"] = doc.id
        data.append(d)

    return jsonify(data)

# ==============================
# EVENTS
# ==============================
@app.route("/events", methods=["GET"])
def get_events():
    docs = db.collection("events").stream()

    events = []
    for doc in docs:
        events.append(doc.to_dict())

    return jsonify(events)

# ==============================
# REGISTER EVENT
# ==============================
@app.route("/register-event", methods=["POST"])
def register_event():
    uid, err = verify_user()
    if err:
        return jsonify({"error": err[0]}), err[1]

    data = request.get_json()

    db.collection("registrations").add({
        "uid": uid,
        "event": data.get("event"),
        "time": datetime.utcnow()
    })

    return jsonify({"message": "Registered"})

# ==============================
# MENTORS
# ==============================
@app.route("/mentors", methods=["GET"])
def mentors():
    docs = db.collection("mentors").stream()

    data = []
    for doc in docs:
        data.append(doc.to_dict())

    return jsonify(data)

# ==============================
# PROFILE
# ==============================
@app.route("/profile", methods=["POST"])
def profile():
    uid, err = verify_user()
    if err:
        return jsonify({"error": err[0]}), err[1]

    data = request.get_json()

    db.collection("users").document(uid).set({
        "name": data.get("name"),
        "skills": data.get("skills"),
        "region": data.get("region")
    }, merge=True)

    return jsonify({"message": "Profile updated"})

# ==============================
# AI ELIGIBILITY FUNCTION
# ==============================
def check_eligibility(events_data, student_gpa, student_region, student_skills, student_type=None):

    student_region = student_region.lower()
    student_skills = [s.lower().strip() for s in student_skills]

    if student_type:
        student_type = student_type.lower()

    eligible = []

    for row in events_data:

        if student_gpa < row["min_gpa"]:
            continue

        if not (row["region"].lower() == "national" or row["region"].lower() == student_region):
            continue

        event_skills = [s.strip().lower() for s in row["skills"].split(",")]
        if not any(skill in event_skills for skill in student_skills):
            continue

        if student_type:
            if student_type != row["type"].lower():
                continue

        eligible.append({
            "name": row["name"],
            "type": row["type"]
        })

    return eligible

# ==============================
# ELIGIBILITY API
# ==============================
@app.route("/eligibility", methods=["POST"])
def eligibility():

    data = request.get_json()

    student_gpa = float(data.get("gpa"))
    student_region = data.get("region")
    student_skills = data.get("skills")
    student_type = data.get("type")

    docs = db.collection("events").stream()

    events_data = []
    for doc in docs:
        events_data.append(doc.to_dict())

    result = check_eligibility(
        events_data,
        student_gpa,
        student_region,
        student_skills,
        student_type
    )

    return jsonify(result)

# ==============================
# RUN
# ==============================
if __name__ == "__main__":
    app.run(debug=True)