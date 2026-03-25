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
CORS(app, resources={r"/*": {
    "origins": "*",  
    "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    "allow_headers": ["Content-Type", "Authorization"]
}})

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
    }, merge=True)

    user_doc = db.collection("users").document(uid).get()
    user_data = user_doc.to_dict()
    stored_role = user_data.get("role", "")
    
    if stored_role != role:
        return jsonify({"error": f"Incorrect role. You are registered as a {stored_role}."}), 401

    return jsonify({
        "message": "Login successful",
        "idToken": result["idToken"],
        "refreshToken": result["refreshToken"],
        "localId": result["localId"],
        "role": user.custom_claims.get("role") if user.custom_claims else role,
        "name": user_data.get("name", "Student")
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

# ==============================
# PROFILE
# ==============================
@app.route("/profile", methods=["GET"])
def get_profile():
    uid, error = verify_user()
    if error:
        return jsonify({"error": error[0]}), error[1]

    user_doc = db.collection("users").document(uid).get()
    user_data = user_doc.to_dict()

    return jsonify({
        "name": user_data.get("name", ""),
        "email": user_data.get("email", ""),
        "region": user_data.get("region", ""),
        "phone": user_data.get("phone", ""),
        "university": user_data.get("university", ""),
        "major": user_data.get("major", ""),
        "gpa": user_data.get("gpa", ""),
        "photo": user_data.get("photo", "")
    }), 200

@app.route("/profile", methods=["PUT"])
def update_profile():
    uid, error = verify_user()
    if error:
        return jsonify({"error": error[0]}), error[1]

    data = request.get_json()

    update_data = {}
    if data.get("name"): update_data["name"] = data["name"]
    if data.get("region"): update_data["region"] = data["region"]
    if data.get("phone"): update_data["phone"] = data["phone"]
    if data.get("university"): update_data["university"] = data["university"]
    if data.get("major"): update_data["major"] = data["major"]
    if data.get("gpa"): update_data["gpa"] = data["gpa"]

    db.collection("users").document(uid).update(update_data)

    return jsonify({"message": "Profile updated successfully"}), 200

@app.route("/profile/email", methods=["PUT"])
def update_email():
    uid, error = verify_user()
    if error:
        return jsonify({"error": error[0]}), error[1]

    data = request.get_json()
    new_email = data.get("email")

    if not new_email:
        return jsonify({"error": "No email provided"}), 400

    try:
        # Update email in Firebase Auth
        auth.update_user(uid, email=new_email, email_verified=False)

        # Update email in Firestore
        db.collection("users").document(uid).update({"email": new_email})

        # Send verification email to new address
        id_token = request.headers.get("Authorization")
        verification_url = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={FIREBASE_API_KEY}"
        requests.post(verification_url, json={
            "requestType": "VERIFY_EMAIL",
            "idToken": id_token
        })

        return jsonify({"message": "Email updated! Please verify your new email address."}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/profile/photo", methods=["PUT"])
def update_photo():
    uid, error = verify_user()
    if error:
        return jsonify({"error": error[0]}), error[1]

    data = request.get_json()
    photo = data.get("photo")

    if not photo:
        return jsonify({"error": "No photo provided"}), 400

    db.collection("users").document(uid).update({"photo": photo})

    return jsonify({"message": "Photo updated successfully"}), 200

@app.route("/profile/delete", methods=["DELETE"])
def delete_account():
    uid, error = verify_user()
    if error:
        return jsonify({"error": error[0]}), error[1]

    try:
        # Delete from Firestore
        db.collection("users").document(uid).delete()

        # Delete from Firebase Auth
        auth.delete_user(uid)

        return jsonify({"message": "Account deleted successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ==============================
# POSTS (Mentor → Student)
# ==============================

# CREATE POST
@app.route("/posts", methods=["POST"])
def create_post():
    uid, error = verify_user()
    if error:
        return jsonify({"error": error[0]}), error[1]

    data = request.get_json()
    title = data.get("title")
    description = data.get("description")
    post_type = data.get("type")  # workshop, internship, scholarship, hackathon
    date = data.get("date", "")
    time = data.get("time", "")
    location = data.get("location", "")
    link = data.get("link", "")
    funding = data.get("funding", "")
    deadline = data.get("deadline", "")

    valid_types = ["workshop", "internship", "scholarship", "hackathon"]
    if not title or not description or post_type not in valid_types:
        return jsonify({"error": "Title, description and valid type are required"}), 400

    # Get mentor name
    mentor_doc = db.collection("users").document(uid).get()
    mentor_data = mentor_doc.to_dict()
    mentor_name = mentor_data.get("name", "Unknown Mentor")

    db.collection("posts").add({
        "title": title,
        "description": description,
        "type": post_type,
        "date": date,
        "time": time,
        "location": location,
        "link": link,
        "funding": funding,
        "deadline": deadline,
        "mentor_id": uid,
        "mentor_name": mentor_name,
        "created_at": datetime.utcnow()
    })

    return jsonify({"message": "Post created successfully"}), 201


# GET POSTS BY TYPE
@app.route("/posts/<post_type>", methods=["GET"])
def get_posts(post_type):
    uid, error = verify_user()
    if error:
        return jsonify({"error": error[0]}), error[1]

    valid_types = ["workshop", "internship", "scholarship", "hackathon"]
    if post_type not in valid_types:
        return jsonify({"error": "Invalid post type"}), 400

    posts_ref = db.collection("posts") \
        .where("type", "==", post_type) \
        .order_by("created_at", direction=firestore.Query.DESCENDING)

    docs = posts_ref.stream()
    posts = []
    for doc in docs:
        data = doc.to_dict()
        data["id"] = doc.id
        # Convert timestamp to string
        if "created_at" in data:
            data["created_at"] = data["created_at"].strftime("%b %d, %Y")
        posts.append(data)

    return jsonify(posts), 200


# GET MENTOR'S OWN POSTS
@app.route("/posts/my/all", methods=["GET"])
def get_my_posts():
    uid, error = verify_user()
    if error:
        return jsonify({"error": error[0]}), error[1]

    posts_ref = db.collection("posts") \
        .where("mentor_id", "==", uid) \
        .order_by("created_at", direction=firestore.Query.DESCENDING)

    docs = posts_ref.stream()
    posts = []
    for doc in docs:
        data = doc.to_dict()
        data["id"] = doc.id
        if "created_at" in data:
            data["created_at"] = data["created_at"].strftime("%b %d, %Y")
        posts.append(data)

    return jsonify(posts), 200


# DELETE POST
@app.route("/posts/<post_id>", methods=["DELETE"])
def delete_post(post_id):
    uid, error = verify_user()
    if error:
        return jsonify({"error": error[0]}), error[1]

    post_ref = db.collection("posts").document(post_id)
    post = post_ref.get()

    if not post.exists:
        return jsonify({"error": "Post not found"}), 404

    if post.to_dict().get("mentor_id") != uid:
        return jsonify({"error": "Unauthorized"}), 403

    post_ref.delete()
    return jsonify({"message": "Post deleted"}), 200


# UPDATE POST
@app.route("/posts/<post_id>", methods=["PUT"])
def update_post(post_id):
    uid, error = verify_user()
    if error:
        return jsonify({"error": error[0]}), error[1]

    post_ref = db.collection("posts").document(post_id)
    post = post_ref.get()

    if not post.exists:
        return jsonify({"error": "Post not found"}), 404

    if post.to_dict().get("mentor_id") != uid:
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    post_ref.update({
        "title": data.get("title"),
        "description": data.get("description"),
        "date": data.get("date", ""),
        "time": data.get("time", ""),
        "location": data.get("location", ""),
        "link": data.get("link", ""),
        "funding": data.get("funding", ""),
        "deadline": data.get("deadline", "")
    })

    return jsonify({"message": "Post updated"}), 200

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