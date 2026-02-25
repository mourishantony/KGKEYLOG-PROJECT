from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from datetime import datetime, timedelta
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId
from dotenv import load_dotenv
import smtplib
import threading
import time
import os

# Load environment variables
load_dotenv()

# MongoDB Connection (supports both local and Atlas)
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = os.getenv("MONGO_DB_NAME", "user_database")

client = MongoClient(MONGO_URI)
db = client[DB_NAME]

users_collection = db["users"]
staff_collection = db["staff"]
lab_collection = db["labs"]
temp_logs = db["temp_logs"]
permanent_logs = db["permanent_logs"]
security_collection = db["security"]
settings_collection = db["settings"]

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "your_secret_key")

# Email Configuration from .env
EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
WATCHMAN_EMAIL = os.getenv("WATCHMAN_EMAIL")
CHIEF_AUTHORITY_EMAIL = os.getenv("CHIEF_AUTHORITY_EMAIL")

# Default Time Limits (seconds) - these are overridden by DB settings
DEFAULT_TIME_LIMIT_1 = 15
DEFAULT_TIME_LIMIT_2 = 30
DEFAULT_TIME_LIMIT_3 = 60

def get_time_limits():
    """Fetch time limits from the database. Falls back to defaults."""
    settings = settings_collection.find_one({"key": "time_limits"})
    if settings:
        return (
            settings.get("time_limit_1", DEFAULT_TIME_LIMIT_1),
            settings.get("time_limit_2", DEFAULT_TIME_LIMIT_2),
            settings.get("time_limit_3", DEFAULT_TIME_LIMIT_3)
        )
    return (DEFAULT_TIME_LIMIT_1, DEFAULT_TIME_LIMIT_2, DEFAULT_TIME_LIMIT_3)

def init_settings():
    """Initialize default settings in DB if they don't exist."""
    if not settings_collection.find_one({"key": "time_limits"}):
        settings_collection.insert_one({
            "key": "time_limits",
            "time_limit_1": DEFAULT_TIME_LIMIT_1,
            "time_limit_2": DEFAULT_TIME_LIMIT_2,
            "time_limit_3": DEFAULT_TIME_LIMIT_3,
            "label_1": "Watchman Alert",
            "label_2": "Staff Reminder",
            "label_3": "Chief Authority Escalation"
        })

init_settings()

def send_email(to_email, subject, message):
    """Function to send an email."""
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            email_message = f"Subject: {subject}\n\n{message}"
            server.sendmail(EMAIL_SENDER, to_email, email_message)
        print(f"✅ Email sent to {to_email}")
    except Exception as e:
        print(f"❌ Error sending email: {e}")

def monitor_key_return(staff_rfid, lab_rfid, staff_name, lab_name, staff_email):
    """Monitor key return and send alerts. Reads time limits from DB each cycle."""
    entry = temp_logs.find_one({"staff_rfid": staff_rfid, "lab_rfid": lab_rfid})
    if not entry:
        return

    taken_time = entry["taken_at"]

    # Read current time limits from DB (admin can change these at any time)
    t1, t2, t3 = get_time_limits()

    time.sleep(t1)
    entry = temp_logs.find_one({"staff_rfid": staff_rfid, "lab_rfid": lab_rfid})
    if entry:
        send_email(WATCHMAN_EMAIL, "Key Return Delay Alert",
                   f"{staff_name} has not returned the key for {lab_name}.\nKey Taken At: {taken_time}")

    time.sleep(t2 - t1)
    entry = temp_logs.find_one({"staff_rfid": staff_rfid, "lab_rfid": lab_rfid})
    if entry:
        send_email(staff_email, "Key Return Reminder",
                   f"Dear {staff_name}, please return the key for {lab_name} immediately.\nKey Taken At: {taken_time}")

    time.sleep(t3 - t2)
    entry = temp_logs.find_one({"staff_rfid": staff_rfid, "lab_rfid": lab_rfid})
    if entry:
        send_email(CHIEF_AUTHORITY_EMAIL, "Key Return Escalation",
                   f"{staff_name} has still not returned the key for {lab_name}. Immediate action required!\nKey Taken At: {taken_time}")

@app.route("/", methods=["GET", "POST"])
def login():
    """Login page."""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = users_collection.find_one({"username": username})
        if user and check_password_hash(user["password"], password):
            session["username"] = username
            session["role"] = user.get("role", "user")
            return redirect(url_for("home"))
        else:
            flash("❌ Invalid credentials!", "danger")
    return render_template("login.html")

@app.route("/get_staff_name", methods=["POST"])
def get_staff_name():
    """Return staff name for a given RFID."""
    data = request.get_json()
    rfid = data.get("rfid", "").strip()
    staff = staff_collection.find_one({"staff_rfid": rfid})
    if staff:
        return jsonify({"name": staff["name"]})
    security = security_collection.find_one({"security_rfid": rfid})
    if security:
        return jsonify({"name": security["name"]})
    return jsonify({"error": "RFID not found"}), 404

@app.route("/home", methods=["GET", "POST"])
def home():
    """Home page."""
    if "username" not in session:
        return redirect(url_for("login"))

    message = ""
    is_admin = session.get("role") == "admin"

    if request.method == "POST":
        try:
            data = request.get_json()
            print("Received data:", data)  # Debugging output

            security_rfid = data.get("security")
            staff_rfid = data.get("staff")
            lab_rfid = data.get("rfid")

            if not security_rfid or not staff_rfid or not lab_rfid:
                return jsonify({"message": "❌ Please enter all RFID details!"})

            try:
                staff = staff_collection.find_one({"staff_rfid": staff_rfid})
                lab = lab_collection.find_one({"lab_rfid": lab_rfid})
                security_personnel = security_collection.find_one({"security_rfid": security_rfid})
            except Exception as e:
                print("Database query error:", e)
                return jsonify({"message": "⚠️ Error querying the database."})

            if not staff and not security_personnel:
                return jsonify({"message": "❌ Invalid Staff or Security RFID!"})

            if not lab:
                return jsonify({"message": "❌ Invalid Lab RFID!"})

            staff_name = staff["name"] if staff else security_personnel["name"]
            staff_email = (
                staff.get("email", "default_email@example.com") if staff 
                else security_personnel.get("email", "default_email@example.com")
            )

            try:
                existing_entry = temp_logs.find_one({"lab_rfid": lab_rfid})
            except Exception as e:
                print("Error checking existing logs:", e)
                return jsonify({"message": "⚠️ Error accessing logs."})

            if existing_entry:
                if existing_entry["staff_rfid"] == staff_rfid:
                    try:
                        temp_logs.delete_one({"lab_rfid": lab_rfid})
                        permanent_logs.update_one(
                            {"staff_rfid": staff_rfid, "lab_rfid": lab_rfid, "status": "taken"},
                            {"$set": {"status": "returned", "returned_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S')}}
                        )
                        message = f"🔑 Key for {lab['lab_name']} returned by {staff_name}."
                    except Exception as e:
                        print("Error updating return status:", e)
                        return jsonify({"message": "⚠️ Error updating return status in database."})
                else:
                    message = f"⚠️ Key for {lab['lab_name']} is already taken."
            else:
                try:
                    temp_logs.insert_one({
                        "staff_rfid": staff_rfid,
                        "staff_name": staff_name,
                        "lab_rfid": lab_rfid,
                        "lab_name": lab["lab_name"],
                        "taken_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    })
                    
                    permanent_logs.insert_one({
                        "staff_rfid": staff_rfid,
                        "staff_name": staff_name,
                        "lab_rfid": lab_rfid,
                        "lab_name": lab["lab_name"],
                        "security_rfid": security_rfid,
                        "taken_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        "status": "taken"
                    })

                    threading.Thread(target=monitor_key_return, args=(
                        staff_rfid, lab_rfid, staff_name, lab["lab_name"], staff_email
                    )).start()

                    message = f"✅ {staff_name} took the key for {lab['lab_name']}."
                except Exception as e:
                    print("Error inserting log data:", e)
                    return jsonify({"message": "⚠️ Error inserting log data into database."})

            return jsonify({"message": message})

        except Exception as e:
            print("Unexpected error:", e)
            return jsonify({"message": "⚠️ An unexpected error occurred!"})

    return render_template("home.html", message=message, is_admin=is_admin)


@app.route("/admin")
def admin_panel():
    """Admin panel page - only accessible by admin users."""
    if "username" not in session:
        return redirect(url_for("login"))
    if session.get("role") != "admin":
        flash("❌ Access denied! Admin only.", "danger")
        return redirect(url_for("home"))

    users = list(users_collection.find())
    staff = list(staff_collection.find())
    labs = list(lab_collection.find())
    security = list(security_collection.find())

    # Convert ObjectId to string for template
    for u in users:
        u["_id"] = str(u["_id"])
    for s in staff:
        s["_id"] = str(s["_id"])
    for l in labs:
        l["_id"] = str(l["_id"])
    for sec in security:
        sec["_id"] = str(sec["_id"])

    # Fetch current time limit settings
    settings = settings_collection.find_one({"key": "time_limits"}) or {}

    return render_template("admin.html", users=users, staff=staff, labs=labs, security=security, settings=settings)


# ===================== ADMIN API ROUTES =====================

def admin_required(f):
    """Decorator to restrict routes to admin users."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return jsonify({"error": "Not logged in"}), 401
        if session.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated


# --- USER MANAGEMENT ---

@app.route("/admin/add_user", methods=["POST"])
@admin_required
def add_user():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    role = data.get("role", "user").strip()

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    if users_collection.find_one({"username": username}):
        return jsonify({"error": "Username already exists."}), 400

    users_collection.insert_one({
        "username": username,
        "password": generate_password_hash(password),
        "role": role
    })
    return jsonify({"message": f"User '{username}' added successfully."})


@app.route("/admin/edit_user", methods=["POST"])
@admin_required
def edit_user():
    data = request.get_json()
    user_id = data.get("id")
    username = data.get("username", "").strip()
    role = data.get("role", "user").strip()
    password = data.get("password", "").strip()

    if not user_id or not username:
        return jsonify({"error": "User ID and username are required."}), 400

    update_fields = {"username": username, "role": role}
    if password:
        update_fields["password"] = generate_password_hash(password)

    users_collection.update_one({"_id": ObjectId(user_id)}, {"$set": update_fields})
    return jsonify({"message": f"User '{username}' updated successfully."})


@app.route("/admin/delete_user", methods=["POST"])
@admin_required
def delete_user():
    data = request.get_json()
    user_id = data.get("id")

    if not user_id:
        return jsonify({"error": "User ID is required."}), 400

    # Prevent deleting yourself
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if user and user["username"] == session["username"]:
        return jsonify({"error": "You cannot delete your own account."}), 400

    users_collection.delete_one({"_id": ObjectId(user_id)})
    return jsonify({"message": "User deleted successfully."})


# --- STAFF MANAGEMENT ---

@app.route("/admin/add_staff", methods=["POST"])
@admin_required
def add_staff():
    data = request.get_json()
    staff_rfid = data.get("staff_rfid", "").strip()
    name = data.get("name", "").strip()
    email = data.get("email", "").strip()

    if not staff_rfid or not name or not email:
        return jsonify({"error": "All fields are required."}), 400

    if staff_collection.find_one({"staff_rfid": staff_rfid}):
        return jsonify({"error": "Staff RFID already exists."}), 400

    staff_collection.insert_one({"staff_rfid": staff_rfid, "name": name, "email": email})
    return jsonify({"message": f"Staff '{name}' added successfully."})


@app.route("/admin/edit_staff", methods=["POST"])
@admin_required
def edit_staff():
    data = request.get_json()
    staff_id = data.get("id")
    staff_rfid = data.get("staff_rfid", "").strip()
    name = data.get("name", "").strip()
    email = data.get("email", "").strip()

    if not staff_id or not staff_rfid or not name or not email:
        return jsonify({"error": "All fields are required."}), 400

    staff_collection.update_one(
        {"_id": ObjectId(staff_id)},
        {"$set": {"staff_rfid": staff_rfid, "name": name, "email": email}}
    )
    return jsonify({"message": f"Staff '{name}' updated successfully."})


@app.route("/admin/delete_staff", methods=["POST"])
@admin_required
def delete_staff():
    data = request.get_json()
    staff_id = data.get("id")
    if not staff_id:
        return jsonify({"error": "Staff ID is required."}), 400
    staff_collection.delete_one({"_id": ObjectId(staff_id)})
    return jsonify({"message": "Staff deleted successfully."})


# --- LAB MANAGEMENT ---

@app.route("/admin/add_lab", methods=["POST"])
@admin_required
def add_lab():
    data = request.get_json()
    lab_rfid = data.get("lab_rfid", "").strip()
    lab_name = data.get("lab_name", "").strip()

    if not lab_rfid or not lab_name:
        return jsonify({"error": "All fields are required."}), 400

    if lab_collection.find_one({"lab_rfid": lab_rfid}):
        return jsonify({"error": "Lab RFID already exists."}), 400

    lab_collection.insert_one({"lab_rfid": lab_rfid, "lab_name": lab_name})
    return jsonify({"message": f"Lab '{lab_name}' added successfully."})


@app.route("/admin/edit_lab", methods=["POST"])
@admin_required
def edit_lab():
    data = request.get_json()
    lab_id = data.get("id")
    lab_rfid = data.get("lab_rfid", "").strip()
    lab_name = data.get("lab_name", "").strip()

    if not lab_id or not lab_rfid or not lab_name:
        return jsonify({"error": "All fields are required."}), 400

    lab_collection.update_one(
        {"_id": ObjectId(lab_id)},
        {"$set": {"lab_rfid": lab_rfid, "lab_name": lab_name}}
    )
    return jsonify({"message": f"Lab '{lab_name}' updated successfully."})


@app.route("/admin/delete_lab", methods=["POST"])
@admin_required
def delete_lab():
    data = request.get_json()
    lab_id = data.get("id")
    if not lab_id:
        return jsonify({"error": "Lab ID is required."}), 400
    lab_collection.delete_one({"_id": ObjectId(lab_id)})
    return jsonify({"message": "Lab deleted successfully."})


# --- SECURITY MANAGEMENT ---

@app.route("/admin/add_security", methods=["POST"])
@admin_required
def add_security():
    data = request.get_json()
    security_rfid = data.get("security_rfid", "").strip()
    name = data.get("name", "").strip()
    email = data.get("email", "").strip()

    if not security_rfid or not name or not email:
        return jsonify({"error": "All fields are required."}), 400

    if security_collection.find_one({"security_rfid": security_rfid}):
        return jsonify({"error": "Security RFID already exists."}), 400

    security_collection.insert_one({"security_rfid": security_rfid, "name": name, "email": email})
    return jsonify({"message": f"Security '{name}' added successfully."})


@app.route("/admin/edit_security", methods=["POST"])
@admin_required
def edit_security():
    data = request.get_json()
    sec_id = data.get("id")
    security_rfid = data.get("security_rfid", "").strip()
    name = data.get("name", "").strip()
    email = data.get("email", "").strip()

    if not sec_id or not security_rfid or not name or not email:
        return jsonify({"error": "All fields are required."}), 400

    security_collection.update_one(
        {"_id": ObjectId(sec_id)},
        {"$set": {"security_rfid": security_rfid, "name": name, "email": email}}
    )
    return jsonify({"message": f"Security '{name}' updated successfully."})


@app.route("/admin/delete_security", methods=["POST"])
@admin_required
def delete_security():
    data = request.get_json()
    sec_id = data.get("id")
    if not sec_id:
        return jsonify({"error": "Security ID is required."}), 400
    security_collection.delete_one({"_id": ObjectId(sec_id)})
    return jsonify({"message": "Security deleted successfully."})


# --- SETTINGS MANAGEMENT ---

@app.route("/admin/get_settings", methods=["GET"])
@admin_required
def get_settings():
    settings = settings_collection.find_one({"key": "time_limits"})
    if settings:
        return jsonify({
            "time_limit_1": settings.get("time_limit_1", DEFAULT_TIME_LIMIT_1),
            "time_limit_2": settings.get("time_limit_2", DEFAULT_TIME_LIMIT_2),
            "time_limit_3": settings.get("time_limit_3", DEFAULT_TIME_LIMIT_3)
        })
    return jsonify({
        "time_limit_1": DEFAULT_TIME_LIMIT_1,
        "time_limit_2": DEFAULT_TIME_LIMIT_2,
        "time_limit_3": DEFAULT_TIME_LIMIT_3
    })


@app.route("/admin/update_settings", methods=["POST"])
@admin_required
def update_settings():
    data = request.get_json()

    try:
        t1 = int(data.get("time_limit_1", DEFAULT_TIME_LIMIT_1))
        t2 = int(data.get("time_limit_2", DEFAULT_TIME_LIMIT_2))
        t3 = int(data.get("time_limit_3", DEFAULT_TIME_LIMIT_3))
    except (ValueError, TypeError):
        return jsonify({"error": "All time values must be valid numbers (in seconds)."}), 400

    if t1 <= 0 or t2 <= 0 or t3 <= 0:
        return jsonify({"error": "All time values must be positive."}), 400

    if not (t1 < t2 < t3):
        return jsonify({"error": "Time limits must be in ascending order (Alert 1 < Alert 2 < Alert 3)."}), 400

    settings_collection.update_one(
        {"key": "time_limits"},
        {"$set": {
            "time_limit_1": t1,
            "time_limit_2": t2,
            "time_limit_3": t3
        }},
        upsert=True
    )
    # Format seconds to HH:MM for the success message
    def fmt(s):
        return f"{s // 3600:02d}:{(s % 3600) // 60:02d}"
    return jsonify({"message": f"Time limits updated: {fmt(t1)} → {fmt(t2)} → {fmt(t3)}"})


@app.route("/database")
def database():
    """Database page."""
    page = int(request.args.get("page", 1))  
    per_page = 10  

    total_logs = permanent_logs.count_documents({})
    total_pages = (total_logs + per_page - 1) // per_page  

    logs = list(permanent_logs.find().sort("taken_at", -1).skip((page - 1) * per_page).limit(per_page))

    for log in logs:
        security_entry = security_collection.find_one({"security_rfid": log.get("security_rfid")})
        log["security_name"] = security_entry["name"] if security_entry else "N/A"
        taken_at = log.get("taken_at")
        if taken_at:
            if isinstance(taken_at, str):
                taken_at = datetime.strptime(taken_at, "%Y-%m-%d %H:%M:%S")
            log["formatted_taken_at"] = taken_at.strftime("%Y-%m-%d %I:%M %p")

    return render_template("database.html", logs=logs, page=page, total_pages=total_pages)



if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")
