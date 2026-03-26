import os
import requests
import json 
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, auth, firestore
from dotenv import load_dotenv
from google import genai
from google.genai import types

# ==============================
# LOAD ENV VARIABLES
# ==============================
load_dotenv()

# ==============================
# GEMINI CONFIGURATION
# ==============================
gemini_client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

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
    id_token = result["idToken"]
    decoded_token = auth.verify_id_token(id_token)

    if not decoded_token.get("email_verified", False):
        return jsonify({"error": "Please verify your email before logging in."}), 401


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
        "role": stored_role,
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
        name = decoded_token.get("name", "")
        photo_url = decoded_token.get("picture", "")

        user_doc = db.collection("users").document(uid).get()
        if user_doc.exists:
            user_data = user_doc.to_dict()
            stored_role = user_data.get("role", "")
            if stored_role != role:
                return jsonify({"error": f"Incorrect role. You are registered as a {stored_role}."}), 401
        else:
            # New user, set the role and Google profile data
            db.collection("users").document(uid).set({
                "name": name,
                "email": email,
                "photo": photo_url,
                "provider": "google",
                "role": role,
                "created_at": datetime.utcnow()
            })

        return jsonify({
            "message": "Google login successful",
            "uid": uid,
            "role": role
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
# AI RECOMMENDATIONS (Public - No Auth Required)
# ==============================
@app.route("/ai/recommendations/public", methods=["GET"])
def get_public_ai_recommendations():
    """Get top 2 AI recommendations for unauthenticated users (e.g., login page)"""
    
    # 1. Fetch all posts from all types
    all_posts = []
    types_to_fetch = ["scholarship", "internship", "hackathon", "workshop"]
    for post_type in types_to_fetch:
        docs = db.collection("posts").where("type", "==", post_type).stream()
        for doc in docs:
            data = doc.to_dict()
            data["id"] = doc.id
            data["type"] = post_type
            if "created_at" in data:
                data["created_at"] = data["created_at"].strftime("%b %d, %Y")
            all_posts.append(data)

    if not all_posts:
        return jsonify([]), 200

    # 2. Build prompt for Gemini with generic student profile
    prompt = f"""
You are an academic opportunity matching engine for a student portal in Kerala, India.

GENERIC STUDENT PROFILE:
- A college student interested in growth opportunities
- Open to scholarships, internships, hackathons, and workshops
- Looking for diverse learning experiences
- Located in Kerala, India

AVAILABLE OPPORTUNITIES (JSON):
{json.dumps(all_posts, indent=2)}

TASK:
Select the top 2 most compelling and diverse opportunities that would appeal to a general college student.
Aim for variety (e.g., one scholarship + one internship, or hackathon + workshop).
For each, provide a short 1-sentence reason why it's beneficial.
Score each opportunity from 0 to 100.

RETURN ONLY valid JSON in this exact format, no markdown, no extra text:
{{
  "recommendations": [
    {{
      "post_id": "<id from the opportunity>",
      "score": <0-100>,
      "match_reason": "<1 sentence why this is great>"
    }}
  ]
}}
"""

    try:
        response = gemini_client.models.generate_content(
            model="gemini-1.5-flash",
            contents=prompt
        )
        raw = response.text.strip()
        # Strip markdown fences if present
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        ai_result = json.loads(raw.strip())
        
        # Merge AI scores back into post data
        post_map = {p["id"]: p for p in all_posts}
        enriched = []
        for rec in ai_result.get("recommendations", []):
            post = post_map.get(rec["post_id"])
            if post:
                post["ai_score"] = rec["score"]
                post["match_reason"] = rec["match_reason"]
                enriched.append(post)
        
        if enriched:
            return jsonify(enriched), 200
        
    except Exception as e:
        print("Public AI Recommendation ERROR:", str(e))

    # Fallback: return top 2 most recent posts from different types
    sorted_by_type = {}
    for post in all_posts:
        post_type = post.get("type", "scholarship")
        if post_type not in sorted_by_type:
            sorted_by_type[post_type] = []
        sorted_by_type[post_type].append(post)
    
    fallback = []
    for post_type in ["scholarship", "internship", "hackathon", "workshop"]:
        if post_type in sorted_by_type and len(fallback) < 2:
            top_post = sorted_by_type[post_type][0]
            top_post["ai_score"] = 75
            top_post["match_reason"] = f"Popular {post_type} opportunity"
            fallback.append(top_post)
    
    return jsonify(fallback), 200

# ==============================
# AI RECOMMENDATIONS (Authenticated)
# ==============================
@app.route("/ai/recommendations", methods=["GET"])
def get_ai_recommendations():
    uid, error = verify_user()
    if error:
        return jsonify({"error": error[0]}), error[1]

    # 1. Fetch student profile
    user_doc = db.collection("users").document(uid).get()
    if not user_doc.exists:
        return jsonify({"error": "Profile not found"}), 404
    profile = user_doc.to_dict()

    # 2. Fetch posts (filtered by type if provided)
    post_type_filter = request.args.get("type", None)
    all_posts = []
    types_to_fetch = [post_type_filter] if post_type_filter else ["scholarship", "internship", "hackathon", "workshop"]
    for post_type in types_to_fetch:
        docs = db.collection("posts").where("type", "==", post_type).stream()
        for doc in docs:
            data = doc.to_dict()
            data["id"] = doc.id
            if "created_at" in data:
                data["created_at"] = data["created_at"].strftime("%b %d, %Y")
            all_posts.append(data)

    if not all_posts:
        return jsonify([]), 200

    # 3. Build prompt for Gemini
    prompt = f"""
You are an academic opportunity matching engine for a student portal in Kerala, India.

STUDENT PROFILE:
- Name: {profile.get('name', 'Unknown')}
- Major: {profile.get('major', 'Not specified')}
- University: {profile.get('university', 'Not specified')}
- GPA: {profile.get('gpa', 'Not specified')}
- Region: {profile.get('region', 'Not specified')}

AVAILABLE OPPORTUNITIES (JSON):
{json.dumps(all_posts, indent=2)}

TASK:
Analyze the student's profile and rank the top 5 most relevant opportunities for them.
For each, provide a short 1-sentence personalized reason why it matches their profile.
Score each opportunity from 0 to 100.

RETURN ONLY valid JSON in this exact format, no markdown, no extra text:
{{
  "recommendations": [
    {{
      "post_id": "<id from the opportunity>",
      "score": <0-100>,
      "match_reason": "<1 sentence why this fits the student>"
    }}
  ]
}}
"""

    try:
        response = gemini_client.models.generate_content(
            model="gemini-1.5-flash",
            contents=prompt
        )
        raw = response.text.strip()
        # Strip markdown fences if present
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        ai_result = json.loads(raw.strip())
    except Exception as e:
        print("AI ERROR:", str(e))

    # 🔥 fallback instead of crash
    fallback = all_posts[:5]
    for post in fallback:
        post["ai_score"] = 50
        post["match_reason"] = "Recommended based on general relevance"

    return jsonify(fallback), 200

    # 4. Merge AI scores back into post data
    post_map = {p["id"]: p for p in all_posts}
    enriched = []
    for rec in ai_result.get("recommendations", []):
        post = post_map.get(rec["post_id"])
        if post:
            post["ai_score"] = rec["score"]
            post["match_reason"] = rec["match_reason"]
            enriched.append(post)

    return jsonify(enriched), 200


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

    print(f"Fetching posts for type: {post_type}, user: {uid}")

    valid_types = ["workshop", "internship", "scholarship", "hackathon"]
    if post_type not in valid_types:
        return jsonify({"error": "Invalid post type"}), 400

    posts_ref = db.collection("posts") \
        .where("type", "==", post_type)

    docs = posts_ref.stream()
    posts = []
    for doc in docs:
        data = doc.to_dict()
        data["id"] = doc.id
        # Convert timestamp to string
        if "created_at" in data:
            data["created_at"] = data["created_at"].strftime("%b %d, %Y")
        posts.append(data)

    # Sort by created_at descending, handling missing dates
    posts.sort(key=lambda x: x.get("created_at", ""), reverse=True)

    print(f"Found {len(posts)} posts")
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
    new_title = data.get("title")
    post_type = post.to_dict().get("type")

    post_ref.update({
        "title": new_title,
        "description": data.get("description"),
        "date": data.get("date", ""),
        "time": data.get("time", ""),
        "location": data.get("location", ""),
        "link": data.get("link", ""),
        "funding": data.get("funding", ""),
        "deadline": data.get("deadline", "")
    })

    # Notify interested users
    try:
        # Note: This requires a composite index for collection group 'interests' with 'post_id' field.
        interests = db.collection_group("interests").where("post_id", "==", post_id).stream()
        for doc in interests:
            # doc.reference is users/{uid}/interests/{post_id}
            # so doc.reference.parent.parent is users/{uid}
            student_uid = doc.reference.parent.parent.id
            if student_uid:
                db.collection("users").document(student_uid).collection("notifications").add({
                    "title": f"Update: {new_title}",
                    "message": f"Organizers have updated the details for \"{new_title}\". Check the new information now!",
                    "type": "event_edit",
                    "priority": "normal",
                    "post_id": post_id,
                    "post_type": post_type,
                    "is_read": False,
                    "created_at": datetime.utcnow()
                })
    except Exception as e:
        print(f"Error notifying users on post update: {e}")

    return jsonify({"message": "Post updated and notifications sent"}), 200

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


# ==================================================
# INTERESTS (Student marks post as "Interested")
# ==================================================

# MARK INTEREST
@app.route("/interests/<post_id>", methods=["POST"])
def add_interest(post_id):
    uid, error = verify_user()
    if error:
        return jsonify({"error": error[0]}), error[1]

    data = request.get_json()
    post_title = data.get("title", "Untitled")
    post_type = data.get("type", "scholarship")
    deadline = data.get("deadline", "")

    # Save interest in user's subcollection
    db.collection("users") \
        .document(uid) \
        .collection("interests") \
        .document(post_id) \
        .set({
            "post_id": post_id,
            "post_type": post_type,
            "post_title": post_title,
            "deadline": deadline,
            "created_at": datetime.utcnow()
        })

    # Create a notification for the interest
    db.collection("users") \
        .document(uid) \
        .collection("notifications") \
        .add({
            "title": f"Interest Marked: {post_title}",
            "message": f"You expressed interest in this {post_type}. We'll notify you as the deadline approaches.",
            "type": "interest",
            "priority": "normal",
            "post_id": post_id,
            "post_type": post_type,
            "is_read": False,
            "created_at": datetime.utcnow()
        })

    return jsonify({"message": "Interest saved"}), 201


# REMOVE INTEREST
@app.route("/interests/<post_id>", methods=["DELETE"])
def remove_interest(post_id):
    uid, error = verify_user()
    if error:
        return jsonify({"error": error[0]}), error[1]

    db.collection("users") \
        .document(uid) \
        .collection("interests") \
        .document(post_id) \
        .delete()

    return jsonify({"message": "Interest removed"}), 200


# GET ALL INTERESTS
@app.route("/interests", methods=["GET"])
def get_interests():
    uid, error = verify_user()
    if error:
        return jsonify({"error": error[0]}), error[1]

    interests_ref = db.collection("users") \
        .document(uid) \
        .collection("interests")

    docs = interests_ref.stream()

    interests = []
    for doc in docs:
        data = doc.to_dict()
        data["id"] = doc.id
        if "created_at" in data and hasattr(data["created_at"], "strftime"):
            data["created_at"] = data["created_at"].strftime("%b %d, %Y")
        interests.append(data)

    return jsonify(interests), 200


# DEADLINE ALERTS — checks interests and generates notifications
@app.route("/notifications/deadline-alerts", methods=["GET"])
def get_deadline_alerts():
    uid, error = verify_user()
    if error:
        return jsonify({"error": error[0]}), error[1]

    interests_ref = db.collection("users") \
        .document(uid) \
        .collection("interests")

    docs = interests_ref.stream()
    now = datetime.utcnow()
    alerts = []

    for doc in docs:
        data = doc.to_dict()
        deadline_str = data.get("deadline", "")
        if not deadline_str:
            continue

        # Try to parse deadline in multiple formats
        deadline_date = None
        formats_to_try = [
            "%Y-%m-%d",
            "%b %d, %Y",
            "%B %d, %Y",
            "%d/%m/%Y",
            "%m/%d/%Y",
            "%d-%m-%Y",
        ]
        for fmt in formats_to_try:
            try:
                deadline_date = datetime.strptime(deadline_str, fmt)
                break
            except ValueError:
                continue

        if not deadline_date:
            continue

        days_remaining = (deadline_date - now).days

        # Only alert for deadlines within 7 days and not yet passed
        if days_remaining < 0 or days_remaining > 7:
            continue

        # Determine urgency
        if days_remaining <= 1:
            priority = "critical"
            urgency_label = "🔴 DEADLINE TODAY!" if days_remaining == 0 else "🔴 1 DAY LEFT!"
        elif days_remaining <= 3:
            priority = "warning"
            urgency_label = f"🟡 {days_remaining} DAYS LEFT"
        else:
            priority = "info"
            urgency_label = f"🔵 {days_remaining} DAYS LEFT"

        post_title = data.get("post_title", "Untitled")
        post_type = data.get("post_type", "opportunity")
        post_id = data.get("post_id", doc.id)

        alert = {
            "id": f"deadline-{post_id}",
            "title": f"Deadline Approaching: {post_title}",
            "message": f"{urgency_label} — The deadline for this {post_type} is {deadline_str}. Don't miss out!",
            "type": "deadline_alert",
            "priority": priority,
            "post_id": post_id,
            "post_type": post_type,
            "deadline": deadline_str,
            "days_remaining": days_remaining,
            "is_read": False,
            "created_at": now.strftime("%b %d, %Y")
        }
        alerts.append(alert)

        # Auto-create notification if one doesn't already exist for this deadline cycle
        notif_check_id = f"deadline_{post_id}_{now.strftime('%Y-%m-%d')}"
        existing_notif = db.collection("users") \
            .document(uid) \
            .collection("notifications") \
            .document(notif_check_id) \
            .get()

        if not existing_notif.exists:
            db.collection("users") \
                .document(uid) \
                .collection("notifications") \
                .document(notif_check_id) \
                .set({
                    "title": f"⏰ Deadline Approaching: {post_title}",
                    "message": f"{urgency_label} — The deadline for this {post_type} is {deadline_str}.",
                    "type": "deadline_alert",
                    "priority": priority,
                    "post_id": post_id,
                    "post_type": post_type,
                    "is_read": False,
                    "created_at": datetime.utcnow()
                })

    # Sort alerts by days_remaining (most urgent first)
    alerts.sort(key=lambda x: x["days_remaining"])

    return jsonify(alerts), 200


# ==============================
# RUN SERVER
# ==============================
if __name__ == "__main__":
    app.run(debug=True)