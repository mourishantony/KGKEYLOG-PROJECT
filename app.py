from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
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

app = Flask(__name__)
app.config.from_object(Config)

# Initialize Security Extensions
csrf = CSRFProtect(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = '🔒 Please log in to access this page.'
login_manager.login_message_category = 'info'

# Initialize Rate Limiter (FIXED)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
limiter.init_app(app)
# MongoDB Connection using config
client = MongoClient(app.config['MONGODB_URI'])
db = client[app.config['DATABASE_NAME']]

# Collections
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
            logger.info(f"Email sent successfully to {to_email}")
    except Exception as e:
        logger.error(f"Error sending email to {to_email}: {e}")

def monitor_key_return(staff_rfid, lab_rfid, staff_name, lab_name, staff_email):
    """Monitor key return and send alerts. Reads time limits from DB each cycle."""
    entry = temp_logs.find_one({"staff_rfid": staff_rfid, "lab_rfid": lab_rfid})
    if not entry:
        return

    taken_time = entry["taken_at"]
    
    # Get dynamic email settings
    email_settings_collection = db["email_settings"]
    settings = email_settings_collection.find_one({"type": "escalation_settings"})
    
    if settings:
        time_limits = [
            settings.get("time_limit_1", 15),
            settings.get("time_limit_2", 30), 
            settings.get("time_limit_3", 60)
        ]
        escalation_levels = settings.get("escalation_levels", {})
    else:
        # Fallback to default
        time_limits = [TIME_LIMIT_1, TIME_LIMIT_2, TIME_LIMIT_3]
        escalation_levels = {}
    
    # Get lab info to find department
    lab = lab_collection.find_one({"lab_rfid": lab_rfid})
    dept_id = lab.get("department") if lab else None
    
    # Level 1: Security notification
    time.sleep(time_limits[0])
    entry = temp_logs.find_one({"staff_rfid": staff_rfid, "lab_rfid": lab_rfid})
    if entry:
        recipients = get_escalation_recipients("level_1", dept_id)
        message = f"🔔 LEVEL 1 ALERT: {staff_name} has not returned the key for {lab_name}.\nKey Taken At: {taken_time}"
        
        for email in recipients:
            send_email(email, "Key Return Delay Alert - Level 1", message)

    # Level 2: Department HOD + Staff notification  
    time.sleep(time_limits[1] - time_limits[0])
    entry = temp_logs.find_one({"staff_rfid": staff_rfid, "lab_rfid": lab_rfid})
    if entry:
        recipients = get_escalation_recipients("level_2", dept_id)
        recipients.append(staff_email)  # Add staff email
        
        message = f"🔔 LEVEL 2 ALERT: {staff_name}, please return the key for {lab_name} immediately.\nKey Taken At: {taken_time}\n\nThis is an urgent reminder."
        
        for email in recipients:
            send_email(email, "URGENT: Key Return Reminder - Level 2", message)

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
def force_logout_user():
    """Force complete logout of current user"""
    try:
        if current_user.is_authenticated:
            logout_user()
        session.clear()
        
        # Clear Flask-Login session keys
        keys_to_remove = []
        for key in session.keys():
            if key.startswith('_user_id') or key.startswith('_fresh'):
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            session.pop(key, None)
            
    except Exception as e:
        logger.error(f"Error during force logout: {e}")
        session.clear()

@app.route("/", methods=["GET", "POST"])
@limiter.limit("10 per minute")
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
    except Exception as e:
        # If there's any issue with current_user, clear session and continue
        logger.warning(f"Authentication check error: {e}")
        session.clear()
    
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = bool(request.form.get('remember'))

        # Input validation
        if not username or not password:
            log_security_event("LOGIN_ATTEMPT_MISSING_CREDENTIALS", username)
            flash("❌ Please enter both username and password!", "danger")
            return render_template("login.html")

        logger.info(f"Login attempt for username: {username}")

        try:
            user = User.get(username, db_obj)

            if user and user.check_password(password):
                # Clear any existing session data before login
                session.clear()
                
                login_user(user, remember=remember, fresh=True)
                logger.info(f"Successful login for user: {username}")
                log_security_event("LOGIN_SUCCESS", username)
                flash("✅ Login successful!", "success")

                # Redirect to next page if specified, otherwise home
                next_page = request.args.get('next')
                if next_page and next_page.startswith('/'):
                    return redirect(next_page)
                return redirect(url_for("home"))
            else:
                logger.warning(f"Failed login attempt for username: {username}")
                log_security_event("LOGIN_FAILED", username, "Invalid credentials")
                flash("❌ Invalid credentials!", "danger")

        except Exception as e:
            logger.error(f"Login error for user {username}: {e}")
            log_security_event("LOGIN_ERROR", username, str(e))
            flash("❌ Login error. Please try again.", "danger")

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
@login_required
@limiter.limit("30 per minute")  # Rate limit RFID submissions
def home():
    """Enhanced home page with security."""
    logger.info(f"User {current_user.username} accessed home page")
    
    message = ""
    is_admin = session.get("role") == "admin"

    if request.method == "POST":
        try:
            # Validate CSRF token is handled automatically by Flask-WTF
            data = request.get_json()
            
            if not data:
                return json_error("❌ No data received!", 400)
            
            logger.info(f"Received RFID data from user {current_user.username}: {data}")

            security_rfid = data.get("security", "").strip()
            staff_rfid = data.get("staff", "").strip()
            lab_rfid = data.get("rfid", "").strip()

            # Enhanced validation
            if not all([security_rfid, staff_rfid, lab_rfid]):
                log_security_event("INVALID_RFID_SUBMISSION", current_user.username, "Missing RFID data")
                return json_error("❌ Please enter all RFID details!", 400)

            # Validate RFID format (basic validation)
            if len(security_rfid) < 3 or len(staff_rfid) < 3 or len(lab_rfid) < 3:
                log_security_event("INVALID_RFID_FORMAT", current_user.username, "RFID too short")
                return json_error("❌ Invalid RFID format!", 400)

            try:
                staff = staff_collection.find_one({"staff_rfid": staff_rfid})
                lab = lab_collection.find_one({"lab_rfid": lab_rfid})
                security_personnel = security_collection.find_one({"security_rfid": security_rfid})
            except Exception as e:
                logger.error(f"Database query error: {e}")
                return json_error("⚠️ Error querying the database.", 500)

            # Check for valid staff/security
            if not staff and not security_personnel:
                log_security_event("INVALID_RFID", current_user.username, f"Staff/Security RFID: {staff_rfid}")
                return json_error("❌ Invalid Staff or Security RFID!", 404)

            # Check for valid lab
            if not lab:
                log_security_event("INVALID_RFID", current_user.username, f"Lab RFID: {lab_rfid}")
                return json_error("❌ Invalid Lab RFID!", 404)

            staff_name = staff["name"] if staff else security_personnel["name"]
            staff_email = (
                staff.get("email", "default_email@example.com") if staff
                else security_personnel.get("email", "default_email@example.com")
            )

            try:
                existing_entry = temp_logs.find_one({"lab_rfid": lab_rfid})
            except Exception as e:
                logger.error(f"Error checking existing logs: {e}")
                return json_error("⚠️ Error accessing logs.", 500)

            # Key return logic
            if existing_entry:
                if existing_entry["staff_rfid"] == staff_rfid:
                    try:
                        temp_logs.delete_one({"lab_rfid": lab_rfid})
                        permanent_logs.update_one(
                            {"staff_rfid": staff_rfid, "lab_rfid": lab_rfid, "status": "taken"},
                            {"$set": {"status": "returned", "returned_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S')}}
                        )
                        message = f"🔑 Key for {lab['lab_name']} returned by {staff_name}."
                        
                        log_security_event("KEY_RETURNED", current_user.username, f"Lab: {lab['lab_name']} | Staff: {staff_name}")

                        # Return success response with additional data
                        return json_success(message, {
                            "action": "key_returned",
                            "staff_name": staff_name,
                            "lab_name": lab['lab_name'],
                            "returned_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        })

                    except Exception as e:
                        logger.error(f"Error updating return status: {e}")
                        return json_error("⚠️ Error updating return status in database.", 500)
                else:
                    # Key already taken by someone else
                    log_security_event("KEY_CONFLICT", current_user.username, f"Lab: {lab['lab_name']} | Attempted by: {staff_name}")
                    return json_error(
                        f"⚠️ Key for {lab['lab_name']} is already taken by {existing_entry['staff_name']}.",
                        409  # Conflict status code
                    )
            else:
                # Key taking logic
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

                    # Start monitoring thread
                    threading.Thread(target=monitor_key_return, args=(
                        staff_rfid, lab_rfid, staff_name, lab["lab_name"], staff_email
                    )).start()

                    message = f"✅ {staff_name} took the key for {lab['lab_name']}."
                    
                    log_security_event("KEY_TAKEN", current_user.username, f"Lab: {lab['lab_name']} | Staff: {staff_name}")

                    # Return success response with additional data
                    return json_success(message, {
                        "action": "key_taken",
                        "staff_name": staff_name,
                        "lab_name": lab['lab_name'],
                        "taken_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    })

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

        except Exception as e:
            logger.error(f"Unexpected error in home route for user {current_user.username}: {e}")
            log_security_event("HOME_ROUTE_ERROR", current_user.username, str(e))
            return json_error("⚠️ An unexpected error occurred!", 500)
    
    return render_template("home.html", message=message, user=current_user)

@app.route("/database")
@login_required
@limiter.limit("20 per minute")  # Rate limit database access
def database():
    """Enhanced database page with security."""
    logger.info(f"User {current_user.username} accessed database page")
    
    # Check permissions - both admin and super_admin can access
    if not current_user.is_super_admin() and not current_user.is_admin():
        logger.warning(f"Non-admin user {current_user.username} attempted to access database")
        log_security_event("UNAUTHORIZED_DATABASE_ACCESS", current_user.username)
        flash("🚫 Access denied. Admin privileges required.", "danger")
        return redirect(url_for("home"))
    
    try:
        page = int(request.args.get("page", 1))
        per_page = 10
        
        # Validate page number
        if page < 1:
            page = 1
            
        total_logs = permanent_logs.count_documents({})
        total_pages = max(1, (total_logs + per_page - 1) // per_page)
        
        # Ensure page doesn't exceed total pages
        if page > total_pages:
            page = total_pages

        logs = list(permanent_logs.find().sort("taken_at", -1).skip((page - 1) * per_page).limit(per_page))

        # Process logs - FIX THE ATTRIBUTE ERROR HERE
        for log in logs:
            # Fix: Use dictionary access instead of dot notation
            security_rfid = log.get("security_rfid")
            if security_rfid:
                security_entry = security_collection.find_one({"security_rfid": security_rfid})
                log["security_name"] = security_entry.get("name") if security_entry else "N/A"
            else:
                log["security_name"] = "N/A"

            # Fix: Properly handle datetime formatting
            taken_at = log.get("taken_at")
            if taken_at:
                try:
                    if isinstance(taken_at, str):
                        taken_at = datetime.strptime(taken_at, "%Y-%m-%d %H:%M:%S")
                    log["formatted_taken_at"] = taken_at.strftime("%Y-%m-%d %I:%M %p")
                except (ValueError, AttributeError) as e:
                    logger.warning(f"Date formatting error: {e}")
                    log["formatted_taken_at"] = str(taken_at)
            else:
                log["formatted_taken_at"] = "N/A"

        log_security_event("DATABASE_ACCESS", current_user.username, f"Page: {page}")
        return render_template("database.html", logs=logs, page=page, total_pages=total_pages, user=current_user)
        
    except Exception as e:
        logger.error(f"Database page error for user {current_user.username}: {e}")
        log_security_event("DATABASE_PAGE_ERROR", current_user.username, str(e))
        flash("❌ Error loading database page.", "danger")
        return redirect(url_for("home"))


@app.route("/super_admin")
@login_required
def super_admin_dashboard():
    """Super Admin Dashboard - RFID Management"""
    if not current_user.is_super_admin() and not current_user.is_admin(): 
        logger.warning(f"Non-super-admin user {current_user.username} attempted to access super admin panel")
        log_security_event("UNAUTHORIZED_SUPER_ADMIN_ACCESS", current_user.username)
        flash("🚫 Access denied. Super Admin privileges required.", "danger")
        return redirect(url_for("home"))
    
    # Get counts for dashboard
    staff_count = staff_collection.count_documents({})
    lab_count = lab_collection.count_documents({})
    security_count = security_collection.count_documents({})
    user_count = users_collection.count_documents({})
    
    log_security_event("SUPER_ADMIN_DASHBOARD_ACCESS", current_user.username)
    
    return render_template("super_admin/dashboard.html", 
                         staff_count=staff_count,
                         lab_count=lab_count, 
                         security_count=security_count,
                         user_count=user_count,
                         user=current_user)

@app.route("/super_admin/staff", methods=["GET", "POST"])
@login_required
def manage_staff():
    """Manage Staff RFID"""
    logger.info(f"Staff management accessed by {current_user.username} with role {current_user.role}")
    
    if not current_user.is_super_admin() and not current_user.is_admin():  # Allow both
        flash("🚫 Access denied. Admin privileges required.", "danger")
        return redirect(url_for("home"))

    if request.method == "POST":
        logger.info(f"POST request received: {request.form}")
        action = request.form.get("action")
        logger.info(f"Action: {action}")
        
        if action == "add":
            staff_data = {
                "staff_rfid": request.form.get("staff_rfid").strip(),
                "name": request.form.get("name").strip(),
                "email": request.form.get("email").strip(),
                "department": request.form.get("department").strip(),
                "created_at": datetime.now(),
                "created_by": current_user.username
            }
            
            # Check if RFID already exists
            if staff_collection.find_one({"staff_rfid": staff_data["staff_rfid"]}):
                flash("❌ Staff RFID already exists!", "danger")
            else:
                staff_collection.insert_one(staff_data)
                log_security_event("STAFF_ADDED", current_user.username, f"RFID: {staff_data['staff_rfid']}")
                flash("✅ Staff added successfully!", "success")
        
        elif action == "delete":
            staff_rfid = request.form.get("staff_rfid")
            result = staff_collection.delete_one({"staff_rfid": staff_rfid})
            if result.deleted_count > 0:
                log_security_event("STAFF_DELETED", current_user.username, f"RFID: {staff_rfid}")
                flash("✅ Staff deleted successfully!", "success")
            else:
                flash("❌ Staff not found!", "danger")
    
    # Get all staff
    staff_list = list(staff_collection.find().sort("name", 1))
    
    return render_template("super_admin/manage_staff.html", 
                         staff_list=staff_list, 
                         user=current_user)

@app.route("/super_admin/labs", methods=["GET", "POST"])
@login_required
def manage_labs():
    """Manage Lab RFID"""
    if not current_user.is_super_admin() and not current_user.is_admin():

        flash("🚫 Access denied. Super Admin privileges required.", "danger")
        return redirect(url_for("home"))
    
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "add":
            lab_data = {
                "lab_rfid": request.form.get("lab_rfid").strip(),
                "lab_name": request.form.get("lab_name").strip(),
                "location": request.form.get("location").strip(),
                "capacity": request.form.get("capacity").strip(),
                "created_at": datetime.now(),
                "created_by": current_user.username
            }
            
            # Check if RFID already exists
            if lab_collection.find_one({"lab_rfid": lab_data["lab_rfid"]}):
                flash("❌ Lab RFID already exists!", "danger")
            else:
                lab_collection.insert_one(lab_data)
                log_security_event("LAB_ADDED", current_user.username, f"RFID: {lab_data['lab_rfid']}")
                flash("✅ Lab added successfully!", "success")
        
        elif action == "delete":
            lab_rfid = request.form.get("lab_rfid")
            result = lab_collection.delete_one({"lab_rfid": lab_rfid})
            if result.deleted_count > 0:
                log_security_event("LAB_DELETED", current_user.username, f"RFID: {lab_rfid}")
                flash("✅ Lab deleted successfully!", "success")
            else:
                flash("❌ Lab not found!", "danger")
    
    # Get all labs
    lab_list = list(lab_collection.find().sort("lab_name", 1))
    
    return render_template("super_admin/manage_labs.html", 
                         lab_list=lab_list, 
                         user=current_user)

@app.route("/super_admin/security", methods=["GET", "POST"])
@login_required
def manage_security():
    """ENHANCED: Manage Security RFID with Smart Username Creation"""
    if not current_user.is_super_admin() and not current_user.is_admin():
        flash("🚫 Access denied. Admin privileges required.", "danger")
        return redirect(url_for("home"))
    
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "add":
            security_rfid = request.form.get("security_rfid").strip()
            name = request.form.get("name").strip()
            email = request.form.get("email").strip()
            shift = request.form.get("shift").strip()
            
            # Check if RFID already exists
            if security_collection.find_one({"security_rfid": security_rfid}):
                flash("❌ Security RFID already exists!", "danger")
            else:
                # ENHANCED: Create memorable username
                username = generate_memorable_username(name, security_rfid)
                default_password = generate_secure_password(security_rfid)
                
                # Create security personnel data
                security_data = {
                    "security_rfid": security_rfid,
                    "name": name,
                    "email": email,
                    "shift": shift,
                    "username": username,  # Store the generated username
                    "created_at": datetime.now(),
                    "created_by": current_user.username
                }
                
                # Create user account for security personnel
                user_data = {
                    "username": username,
                    "password": default_password,
                    "email": email,
                    "role": "security",
                    "security_rfid": security_rfid,
                    "full_name": name,
                    "created_at": datetime.now(),
                    "created_by": current_user.username,
                    "is_active": True,
                    "auto_created": True
                }
                
                try:
                    # Check if username already exists (very unlikely but safety check)
                    if users_collection.find_one({"username": username}):
                        # If collision, add a number
                        counter = 1
                        original_username = username
                        while users_collection.find_one({"username": username}):
                            username = f"{original_username}{counter}"
                            counter += 1
                        user_data["username"] = username
                        security_data["username"] = username
                    
                    # Insert security personnel and user account
                    security_collection.insert_one(security_data)
                    users_collection.insert_one(user_data)
                    
                    log_security_event("SECURITY_AND_USER_ADDED", current_user.username, 
                                     f"RFID: {security_rfid} | Username: {username}")
                    
                    flash(f"✅ Security added! 👤 Username: {username} | 🔐 Password: {default_password}", "success")
                        
                except Exception as e:
                    logger.error(f"Error adding security personnel: {e}")
                    flash("❌ Error adding security personnel!", "danger")
        
        elif action == "delete":
            security_rfid = request.form.get("security_rfid")
            
            try:
                # Get username before deletion
                security_person = security_collection.find_one({"security_rfid": security_rfid})
                username = security_person.get("username") if security_person else f"security_{security_rfid.lower()}"
                
                # Delete security personnel and associated user account
                security_result = security_collection.delete_one({"security_rfid": security_rfid})
                user_result = users_collection.delete_one({"username": username, "auto_created": True})
                
                if security_result.deleted_count > 0:
                    log_security_event("SECURITY_DELETED", current_user.username, 
                                     f"RFID: {security_rfid} | User: {username}")
                    flash("✅ Security personnel and login account deleted successfully!", "success")
                else:
                    flash("❌ Security personnel not found!", "danger")
                    
            except Exception as e:
                logger.error(f"Error deleting security personnel: {e}")
                flash("❌ Error deleting security personnel!", "danger")
    
    # Get all security personnel with their login info
    security_list = []
    for security in security_collection.find().sort("name", 1):
        username = security.get("username") or f"security_{security['security_rfid'].lower()}"
        user_account = users_collection.find_one({"username": username})
        
        security["login_username"] = username
        security["has_login"] = bool(user_account)
        security_list.append(security)
    
    return render_template("super_admin/manage_security.html", 
                         security_list=security_list, 
                         user=current_user)


@app.route("/super_admin/users", methods=["GET", "POST"])
@login_required
def manage_users():
    """Manage System Users"""
    if not current_user.is_super_admin() and not current_user.is_admin():

        flash("🚫 Access denied. Super Admin privileges required.", "danger")
        return redirect(url_for("home"))
    
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "add":
            user_data = {
                "username": request.form.get("username").strip(),
                "password": request.form.get("password"),  # In production, hash this!
                "email": request.form.get("email").strip(),
                "role": request.form.get("role"),
                "created_at": datetime.now(),
                "created_by": current_user.username,
                "is_active": True
            }
            
            # Check if username already exists
            if users_collection.find_one({"username": user_data["username"]}):
                flash("❌ Username already exists!", "danger")
            else:
                users_collection.insert_one(user_data)
                log_security_event("USER_ADDED", current_user.username, f"Username: {user_data['username']} | Role: {user_data['role']}")
                flash("✅ User added successfully!", "success")
        
        elif action == "delete":
            username = request.form.get("username")
            if username == current_user.username:
                flash("❌ Cannot delete your own account!", "danger")
            else:
                result = users_collection.delete_one({"username": username})
                if result.deleted_count > 0:
                    log_security_event("USER_DELETED", current_user.username, f"Username: {username}")
                    flash("✅ User deleted successfully!", "success")
                else:
                    flash("❌ User not found!", "danger")
    
    # Get all users
    user_list = list(users_collection.find().sort("username", 1))
    
    return render_template("super_admin/manage_users.html", 
                         user_list=user_list, 
                         user=current_user)

@app.route("/super_admin/create_security_logins", methods=["POST"])
@login_required
def create_security_logins():
    """Create login accounts for existing security personnel"""
    if not current_user.is_super_admin() and not current_user.is_admin():
        flash("🚫 Access denied. Admin privileges required.", "danger")
        return redirect(url_for("home"))
    
    created_count = 0
    security_credentials = []
    
    try:
        # Get all security personnel without login accounts
        for security in security_collection.find():
            username = generate_memorable_username(security['name'], security['security_rfid'])
            
            # Check if user account already exists
            if not users_collection.find_one({"username": username}):
                default_password = generate_secure_password(security['security_rfid'])
                
                user_data = {
                    "username": username,
                    "password": default_password,
                    "email": security.get("email", ""),
                    "role": "security",
                    "security_rfid": security["security_rfid"],
                    "created_at": datetime.now(),
                    "created_by": current_user.username,
                    "is_active": True,
                    "auto_created": True
                }
                
                users_collection.insert_one(user_data)
                created_count += 1
                
                security_credentials.append({
                    "name": security["name"],
                    "username": username,
                    "password": default_password,
                    "rfid": security["security_rfid"]
                })
        
        if created_count > 0:
            log_security_event("BULK_SECURITY_LOGINS_CREATED", current_user.username, f"Created {created_count} accounts")
            
            # Store credentials in session for display
            session['new_security_credentials'] = security_credentials
            
            flash(f"✅ Created {created_count} login accounts for security personnel!", "success")
        else:
            flash("ℹ️ All security personnel already have login accounts.", "info")
    
    except Exception as e:
        logger.error(f"Error creating bulk security logins: {e}")
        flash("❌ Error creating security login accounts!", "danger")
    
    return redirect(url_for("manage_security"))

def generate_memorable_username(name, rfid):
    """Generate memorable username from name and RFID"""
    # Clean the name - remove spaces, special characters
    clean_name = ''.join(c.lower() for c in name if c.isalpha())
    
    # Option 1: First name + last 3 digits (Most memorable)
    first_name = clean_name.split()[0] if ' ' in name else clean_name[:6]
    last_digits = rfid[-3:]
    username_option1 = f"{first_name}{last_digits}"
    
    # Choose the best option
    if len(username_option1) <= 8:
        return username_option1
    else:
        # Fallback for long names
        name_part = clean_name[:3] if len(clean_name) >= 3 else clean_name
        return f"{name_part}{rfid[-3:]}"

def generate_secure_password(rfid):
    """Generate a more secure but memorable password"""
    # Use first 2 and last 2 digits with a prefix
    if len(rfid) >= 4:
        return f"sec{rfid[:2]}{rfid[-2:]}"
    else:
        return f"sec{rfid}"

@app.route("/super_admin/migrate_security_usernames", methods=["POST"])
@login_required
def migrate_security_usernames():
    """Migrate existing security personnel to new username format"""
    if not current_user.is_super_admin() and not current_user.is_admin():

        flash("🚫 Access denied.", "danger")
        return redirect(url_for("home"))
    
    migrated_count = 0
    migration_results = []
    
    try:
        for security in security_collection.find():
            old_username = f"security_{security['security_rfid'].lower()}"
            new_username = generate_memorable_username(security['name'], security['security_rfid'])
            
            # Update user account
            user_update = users_collection.update_one(
                {"username": old_username},
                {"$set": {"username": new_username}}
            )
            
            # Update security record
            security_collection.update_one(
                {"security_rfid": security['security_rfid']},
                {"$set": {"username": new_username}}
            )
            
            if user_update.modified_count > 0:
                migration_results.append({
                    "name": security['name'],
                    "old_username": old_username,
                    "new_username": new_username
                })
                migrated_count += 1
        
        if migrated_count > 0:
            session['migration_results'] = migration_results
            flash(f"✅ Successfully migrated {migrated_count} security usernames!", "success")
        else:
            flash("ℹ️ No accounts needed migration.", "info")
            
    except Exception as e:
        logger.error(f"Migration error: {e}")
        flash("❌ Error during migration!", "danger")
    
    return redirect(url_for("manage_security"))


@app.route("/super_admin/roles", methods=["GET", "POST"])
@login_required
def manage_roles():
    """Manage System Roles - Dynamic Configuration"""
    if not current_user.is_super_admin() and not current_user.is_admin():

        flash("🚫 Access denied. Super Admin privileges required.", "danger")
        return redirect(url_for("home"))
    
    # Get roles collection for dynamic role storage
    roles_collection = db["roles"]
    
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "create_role":
            role_data = {
                "role_id": request.form.get("role_id").strip(),
                "name": request.form.get("role_name").strip(),
                "description": request.form.get("description").strip(),
                "permissions": request.form.getlist("permissions"),
                "email_level": int(request.form.get("email_level", 0)),
                "can_access_home": bool(request.form.get("can_access_home")),
                "can_view_database": bool(request.form.get("can_view_database")),
                "can_view_all_departments": bool(request.form.get("can_view_all_departments")),
                "created_at": datetime.now(),
                "created_by": current_user.username
            }
            
            # Check if role already exists
            if roles_collection.find_one({"role_id": role_data["role_id"]}):
                flash("❌ Role ID already exists!", "danger")
            else:
                roles_collection.insert_one(role_data)
                log_security_event("ROLE_CREATED", current_user.username, f"Role: {role_data['role_id']}")
                flash("✅ Role created successfully!", "success")
        
        elif action == "update_role":
            role_id = request.form.get("role_id")
            update_data = {
                "name": request.form.get("role_name").strip(),
                "description": request.form.get("description").strip(),
                "permissions": request.form.getlist("permissions"),
                "email_level": int(request.form.get("email_level", 0)),
                "can_access_home": bool(request.form.get("can_access_home")),
                "can_view_database": bool(request.form.get("can_view_database")),
                "can_view_all_departments": bool(request.form.get("can_view_all_departments")),
                "updated_at": datetime.now(),
                "updated_by": current_user.username
            }
            
            result = roles_collection.update_one({"role_id": role_id}, {"$set": update_data})
            if result.modified_count > 0:
                log_security_event("ROLE_UPDATED", current_user.username, f"Role: {role_id}")
                flash("✅ Role updated successfully!", "success")
            else:
                flash("❌ Role not found!", "danger")
        
        elif action == "delete_role":
            role_id = request.form.get("role_id")
            if role_id == "super_admin":
                flash("❌ Cannot delete super_admin role!", "danger")
            else:
                result = roles_collection.delete_one({"role_id": role_id})
                if result.deleted_count > 0:
                    log_security_event("ROLE_DELETED", current_user.username, f"Role: {role_id}")
                    flash("✅ Role deleted successfully!", "success")
                else:
                    flash("❌ Role not found!", "danger")
    
    # Get all roles
    roles_list = list(roles_collection.find().sort("role_id", 1))
    
    # Available permissions
    available_permissions = [
        "home_access", "database_view", "key_management", "department_view",
        "all_view", "email_notifications", "reports", "admin_view", 
        "security_oversight", "user_management"
    ]
    
    return render_template("super_admin/manage_roles.html", 
                         roles_list=roles_list,
                         available_permissions=available_permissions,
                         user=current_user)

@app.route("/super_admin/departments", methods=["GET", "POST"])
@login_required
def manage_departments():
    """Manage Departments for HOD assignments"""
    if not current_user.is_super_admin() and not current_user.is_admin():
        flash("🚫 Access denied. Super Admin privileges required.", "danger")
        return redirect(url_for("home"))
    
    departments_collection = db["departments"]
    
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "add":
            dept_data = {
                "dept_id": request.form.get("dept_id").strip(),
                "dept_name": request.form.get("dept_name").strip(),
                "hod_email": request.form.get("hod_email").strip(),
                "description": request.form.get("description").strip(),
                "created_at": datetime.now(),
                "created_by": current_user.username
            }
            
            if departments_collection.find_one({"dept_id": dept_data["dept_id"]}):
                flash("❌ Department ID already exists!", "danger")
            else:
                departments_collection.insert_one(dept_data)
                log_security_event("DEPARTMENT_ADDED", current_user.username, f"Dept: {dept_data['dept_id']}")
                flash("✅ Department added successfully!", "success")
        
        elif action == "delete":
            dept_id = request.form.get("dept_id")
            result = departments_collection.delete_one({"dept_id": dept_id})
            if result.deleted_count > 0:
                log_security_event("DEPARTMENT_DELETED", current_user.username, f"Dept: {dept_id}")
                flash("✅ Department deleted successfully!", "success")
            else:
                flash("❌ Department not found!", "danger")
    
    # Get all departments
    dept_list = list(departments_collection.find().sort("dept_name", 1))
    
    return render_template("super_admin/manage_departments.html", 
                         dept_list=dept_list,
                         user=current_user)

@app.route("/super_admin/email_settings", methods=["GET", "POST"])
@login_required
def manage_email_settings():
    """Manage Email Escalation Settings"""
    if not current_user.is_super_admin() and not current_user.is_admin():
        flash("🚫 Access denied. Super Admin privileges required.", "danger")
        return redirect(url_for("home"))
    
    email_settings_collection = db["email_settings"]
    
    if request.method == "POST":
        settings_data = {
            "time_limit_1": int(request.form.get("time_limit_1", 15)),
            "time_limit_2": int(request.form.get("time_limit_2", 30)), 
            "time_limit_3": int(request.form.get("time_limit_3", 60)),
            "escalation_levels": {
                "level_1": {
                    "recipients": request.form.getlist("level_1_recipients"),
                    "message_template": request.form.get("level_1_template")
                },
                "level_2": {
                    "recipients": request.form.getlist("level_2_recipients"),
                    "message_template": request.form.get("level_2_template")
                },
                "level_3": {
                    "recipients": request.form.getlist("level_3_recipients"),
                    "message_template": request.form.get("level_3_template")
                }
            },
            "updated_at": datetime.now(),
            "updated_by": current_user.username
        }
        
        # Upsert settings
        email_settings_collection.replace_one(
            {"type": "escalation_settings"}, 
            {"type": "escalation_settings", **settings_data},
            upsert=True
        )
        
        log_security_event("EMAIL_SETTINGS_UPDATED", current_user.username)
        flash("✅ Email settings updated successfully!", "success")
    
    # Get current settings
    current_settings = email_settings_collection.find_one({"type": "escalation_settings"})
    
    # Get all users for recipient selection
    all_users = list(users_collection.find({"role": {"$ne": "super_admin"}}).sort("username", 1))
    
    return render_template("super_admin/email_settings.html",
                         current_settings=current_settings,
                         all_users=all_users,
                         user=current_user)

# Enhanced Error Handlers
@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 - Page Not Found"""
    logger.warning(f"404 error: {request.url} | User: {current_user.username if current_user.is_authenticated else 'Anonymous'}")
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 - Internal Server Error"""
    logger.error(f"500 error: {error} | User: {current_user.username if current_user.is_authenticated else 'Anonymous'}")
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    """Handle 403 - Forbidden"""
    logger.warning(f"403 error: {error} | User: {current_user.username if current_user.is_authenticated else 'Anonymous'}")
    return render_template('errors/403.html'), 403

@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle 429 - Too Many Requests"""
    log_security_event("RATE_LIMIT_EXCEEDED", current_user.username if current_user.is_authenticated else None)
    return jsonify({
        "success": False,
        "message": "⚠️ Too many requests. Please slow down!",
        "retry_after": e.retry_after
    }), 429



@app.route("/debug_session")
def debug_session():
    """Debug route to check session state"""
    return {
        "current_user_authenticated": current_user.is_authenticated if current_user else False,
        "current_user_username": current_user.username if hasattr(current_user, 'username') else 'No username',
        "session_keys": list(session.keys()),
        "session_data": dict(session)
    }

@app.route("/debug_logs")
@login_required
def debug_logs():
    """Debug route to see log structure"""
    if not current_user.is_super_admin() and not current_user.is_admin():
        return "Access denied"
    
    # Get one log to see structure
    sample_log = permanent_logs.find_one()
    if sample_log:
        return {
            "log_structure": dict(sample_log),
            "log_keys": list(sample_log.keys()),
            "log_types": {key: str(type(value)) for key, value in sample_log.items()}
        }
    else:
        return {"message": "No logs found"}
        
@app.route("/test_admin")
@login_required
def test_admin():
    """Test admin access"""
    if not current_user.is_authenticated:
        return "Not authenticated"
    
    return {
        "username": current_user.username,
        "role": current_user.role,
        "is_admin": current_user.is_admin(),
        "is_super_admin": current_user.is_super_admin(),
        "can_view_database": current_user.can_view_database()
    }

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")
