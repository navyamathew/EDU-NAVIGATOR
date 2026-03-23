import os
import requests
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, auth, firestore
from dotenv import load_dotenv

# ==============================
# LOAD ENV VARIABLES
# ==============================
load_dotenv()

app = Flask(__name__)
CORS(app)

# ==============================
# INITIALIZE FIREBASE
# ==============================
if not firebase_admin._apps:
    cred = credentials.Certificate("firebase_config.json")
    firebase_admin.initialize_app(cred)

db = firestore.client()

FIREBASE_API_KEY = os.getenv("FIREBASE_API_KEY")


# ==============================
# TOKEN VERIFICATION HELPER
# ==============================
def verify_user():
    id_token = request.headers.get("Authorization")

    if not id_token:
        return None, ("Missing token", 401)

    try:
        decoded_token = auth.verify_id_token(id_token)
        return decoded_token["uid"], None
    except Exception:
        return None, ("Invalid token", 401)

# ==============================
# REGISTER
# ==============================
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    name = data.get("name")
    email = data.get("email")
    password = data.get("password")
    role = data.get("role", "student")

    if not name or not email or not password:
        return jsonify({"error": "Name, email and password are required"}), 400

    valid_roles = ["student", "mentor", "administrator"]
    if role.lower() not in valid_roles:
        return jsonify({"error": "Invalid role"}), 400
    role = role.lower()

    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={FIREBASE_API_KEY}"

    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True
    }

    response = requests.post(url, json=payload)
    result = response.json()

    if "error" in result:
        return jsonify({"error": result["error"]["message"]}), 400

    uid = result["localId"]

    db.collection("users").document(uid).set({
        "name": name,
        "email": email,
        "role": role,
        "provider": "password",
        "created_at": datetime.utcnow()
    })

    verification_url = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={FIREBASE_API_KEY}"
    requests.post(verification_url, json={
        "requestType": "VERIFY_EMAIL",
        "idToken": result["idToken"]
    })

    return jsonify({
        "message": "Account created! Please check your email to verify your account.",
        "idToken": result["idToken"],
        "localId": uid
    }), 201

# ==============================
# EMAIL & PASSWORD LOGIN
# ==============================
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    email = data.get("email")
    password = data.get("password")
    role = data.get("role", "student")

    valid_roles = ["student", "mentor", "administrator"]
    if role.lower() not in valid_roles:
        return jsonify({"error": "Invalid role"}), 400
    role = role.lower()


    if not email or not password:
        return jsonify({"error": "Missing email or password"}), 400

    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"

    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True
    }

    response = requests.post(url, json=payload)
    result = response.json()

    if "error" in result:
        return jsonify({"error": result["error"]["message"]}), 401

    uid = result["localId"]
    email = result["email"]
    # Check if email is verified
    user = auth.get_user(uid)
    if not user.email_verified:
        return jsonify({"error": "Please verify your email before logging in. Check your inbox!"}), 401
    


    # Save user in Firestore
    db.collection("users").document(uid).set({
        "email": email,
        "provider": "password",
        "role": role
    }, merge=True)

    return jsonify({
        "message": "Login successful",
        "idToken": result["idToken"],
        "refreshToken": result["refreshToken"],
        "localId": result["localId"]
    }), 200


# ==============================
# GOOGLE LOGIN
# ==============================
@app.route("/google-login", methods=["POST"])
def google_login():
    data = request.get_json()
    id_token = data.get("idToken")
    role = data.get("role", "student")

    valid_roles = ["student", "mentor", "administrator"]
    if role.lower() not in valid_roles:
        return jsonify({"error": "Invalid role"}), 400
    role = role.lower()

    if not id_token:
        return jsonify({"error": "Missing ID token"}), 400

    try:
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token["uid"]
        email = decoded_token.get("email")

        db.collection("users").document(uid).set({
            "email": email,
            "provider": "google",
            "role": role
        }, merge=True)

        return jsonify({
            "message": "Google login successful",
            "uid": uid
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 401


# ==============================
# PROTECTED DASHBOARD
# ==============================
@app.route("/dashboard", methods=["GET"])
def dashboard():
    uid, error = verify_user()
    if error:
        return jsonify({"error": error[0]}), error[1]

    return jsonify({
        "message": "Welcome to dashboard",
        "uid": uid
    }), 200


# ==================================================
# NOTIFICATIONS SECTION
# ==================================================

# ADD NOTIFICATION (System Use)
@app.route("/notifications/add", methods=["POST"])
def add_notification():
    uid, error = verify_user()
    if error:
        return jsonify({"error": error[0]}), error[1]

    data = request.get_json()
    title = data.get("title")
    message = data.get("message")
    notif_type = data.get("type", "alert")
    priority = data.get("priority", "normal")

    if not title or not message:
        return jsonify({"error": "Title and message required"}), 400

    db.collection("users") \
        .document(uid) \
        .collection("notifications") \
        .add({
            "title": title,
            "message": message,
            "type": notif_type,
            "priority": priority,
            "is_read": False,
            "created_at": datetime.utcnow()
        })

    return jsonify({"message": "Notification added"}), 201


# GET ALL NOTIFICATIONS
@app.route("/notifications", methods=["GET"])
def get_notifications():
    uid, error = verify_user()
    if error:
        return jsonify({"error": error[0]}), error[1]

    notifications_ref = db.collection("users") \
        .document(uid) \
        .collection("notifications") \
        .order_by("created_at", direction=firestore.Query.DESCENDING)

    docs = notifications_ref.stream()

    notifications = []
    for doc in docs:
        data = doc.to_dict()
        data["id"] = doc.id
        notifications.append(data)

    return jsonify(notifications), 200


# GET UNREAD NOTIFICATIONS
@app.route("/notifications/unread", methods=["GET"])
def get_unread_notifications():
    uid, error = verify_user()
    if error:
        return jsonify({"error": error[0]}), error[1]

    notifications_ref = db.collection("users") \
        .document(uid) \
        .collection("notifications") \
        .where("is_read", "==", False)

    docs = notifications_ref.stream()

    notifications = []
    for doc in docs:
        data = doc.to_dict()
        data["id"] = doc.id
        notifications.append(data)

    return jsonify(notifications), 200


# MARK SINGLE NOTIFICATION AS READ
@app.route("/notifications/<notification_id>/read", methods=["PUT"])
def mark_notification_read(notification_id):
    uid, error = verify_user()
    if error:
        return jsonify({"error": error[0]}), error[1]

    db.collection("users") \
        .document(uid) \
        .collection("notifications") \
        .document(notification_id) \
        .update({"is_read": True})

    return jsonify({"message": "Notification marked as read"}), 200


# MARK ALL NOTIFICATIONS AS READ
@app.route("/notifications/read-all", methods=["PUT"])
def mark_all_read():
    uid, error = verify_user()
    if error:
        return jsonify({"error": error[0]}), error[1]

    notifications_ref = db.collection("users") \
        .document(uid) \
        .collection("notifications")

    docs = notifications_ref.stream()

    for doc in docs:
        doc.reference.update({"is_read": True})

    return jsonify({"message": "All notifications marked as read"}), 200


# ==============================
# RUN SERVER
# ==============================
if __name__ == "__main__":
    app.run(debug=True)