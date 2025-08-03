from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
from pymongo import MongoClient
import smtplib
import threading
import time
import logging
from config import Config
from models import User

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

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

# Email Configuration from config
EMAIL_SENDER = app.config['EMAIL_SENDER']
EMAIL_PASSWORD = app.config['EMAIL_PASSWORD']
WATCHMAN_EMAIL = app.config['WATCHMAN_EMAIL']
CHIEF_AUTHORITY_EMAIL = app.config['CHIEF_AUTHORITY_EMAIL']

# Time Limits from config
TIME_LIMIT_1 = app.config['TIME_LIMIT_1']
TIME_LIMIT_2 = app.config['TIME_LIMIT_2']
TIME_LIMIT_3 = app.config['TIME_LIMIT_3']

# Database object for models
class Database:
    def __init__(self):
        self.users_collection = users_collection
        self.staff_collection = staff_collection
        self.lab_collection = lab_collection
        self.temp_logs = temp_logs
        self.permanent_logs = permanent_logs
        self.security_collection = security_collection

db_obj = Database()

@login_manager.user_loader
def load_user(username):
    """Load user for Flask-Login"""
    return User.get(username, db_obj)

# Security Headers Middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Only add HSTS in production with HTTPS
    if not app.debug:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

# Security Event Logging
def log_security_event(event_type, username=None, details=None):
    """Log security events for monitoring"""
    logger.warning(f"SECURITY EVENT: {event_type} | User: {username or 'Anonymous'} | Details: {details or 'None'} | IP: {request.remote_addr}")

# Helper functions
def json_error(message, status_code=400):
    """Helper function for consistent JSON error responses"""
    return jsonify({
        "success": False,
        "message": message,
        "status_code": status_code,
        "timestamp": datetime.now().isoformat()
    }), status_code

def json_success(message, data=None):
    """Helper function for consistent JSON success responses"""
    response = {
        "success": True,
        "message": message,
        "timestamp": datetime.now().isoformat()
    }
    if data:
        response["data"] = data
    return jsonify(response), 200

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
    """Monitor key return and send alerts."""
    entry = temp_logs.find_one({"staff_rfid": staff_rfid, "lab_rfid": lab_rfid})
    if not entry:
        return

    taken_time = entry["taken_at"]
    time.sleep(TIME_LIMIT_1)

    entry = temp_logs.find_one({"staff_rfid": staff_rfid, "lab_rfid": lab_rfid})
    if entry:
        send_email(WATCHMAN_EMAIL, "Key Return Delay Alert",
                  f"{staff_name} has not returned the key for {lab_name}.\nKey Taken At: {taken_time}")

    time.sleep(TIME_LIMIT_2 - TIME_LIMIT_1)
    entry = temp_logs.find_one({"staff_rfid": staff_rfid, "lab_rfid": lab_rfid})
    if entry:
        send_email(staff_email, "Key Return Reminder",
                  f"Dear {staff_name}, please return the key for {lab_name} immediately.\nKey Taken At: {taken_time}")

    time.sleep(TIME_LIMIT_3 - TIME_LIMIT_2)
    entry = temp_logs.find_one({"staff_rfid": staff_rfid, "lab_rfid": lab_rfid})
    if entry:
        send_email(CHIEF_AUTHORITY_EMAIL, "Key Return Escalation",
                  f"{staff_name} has still not returned the key for {lab_name}. Immediate action required!\nKey Taken At: {taken_time}")

@app.route("/", methods=["GET", "POST"])
@limiter.limit("10 per minute")  # Rate limit login attempts
def login():
    """Enhanced login with security features."""
    if current_user.is_authenticated:
        logger.info(f"User {current_user.username} already authenticated, redirecting to home")
        return redirect(url_for("home"))
    
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
                login_user(user, remember=remember)
                logger.info(f"Successful login for user: {username}")
                log_security_event("LOGIN_SUCCESS", username)
                flash("✅ Login successful!", "success")
                
                # Redirect to next page if specified, otherwise home
                next_page = request.args.get('next')
                if next_page and next_page.startswith('/'):  # Security: Only allow relative URLs
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

@app.route("/logout")
@login_required
def logout():
    """Secure logout with session cleanup."""
    username = current_user.username
    logout_user()
    
    # Clear session data
    session.clear()
    
    logger.info(f"User {username} logged out")
    log_security_event("LOGOUT", username)
    flash("✅ You have been logged out successfully!", "success")
    return redirect(url_for("login"))

@app.route("/home", methods=["GET", "POST"])
@login_required
@limiter.limit("30 per minute")  # Rate limit RFID submissions
def home():
    """Enhanced home page with security."""
    logger.info(f"User {current_user.username} accessed home page")
    
    message = ""
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

                except Exception as e:
                    logger.error(f"Error inserting log data: {e}")
                    return json_error("⚠️ Error inserting log data into database.", 500)

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
    
    # Admin-only access
    if not current_user.is_admin():
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

        for log in logs:
            security_entry = security_collection.find_one({"security_rfid": log.get("security_rfid")})
            log["security_name"] = security_entry["name"] if security_entry else "N/A"

            taken_at = log.get("taken_at")
            if taken_at:
                if isinstance(taken_at, str):
                    taken_at = datetime.strptime(taken_at, "%Y-%m-%d %H:%M:%S")
                log["formatted_taken_at"] = taken_at.strftime("%Y-%m-%d %I:%M %p")

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
    if not current_user.is_super_admin():
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
    if not current_user.is_super_admin():
        flash("🚫 Access denied. Super Admin privileges required.", "danger")
        return redirect(url_for("home"))
    
    if request.method == "POST":
        action = request.form.get("action")
        
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
    if not current_user.is_super_admin():
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
    """Manage Security RFID"""
    if not current_user.is_super_admin():
        flash("🚫 Access denied. Super Admin privileges required.", "danger")
        return redirect(url_for("home"))
    
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "add":
            security_data = {
                "security_rfid": request.form.get("security_rfid").strip(),
                "name": request.form.get("name").strip(),
                "email": request.form.get("email").strip(),
                "shift": request.form.get("shift").strip(),
                "created_at": datetime.now(),
                "created_by": current_user.username
            }
            
            # Check if RFID already exists
            if security_collection.find_one({"security_rfid": security_data["security_rfid"]}):
                flash("❌ Security RFID already exists!", "danger")
            else:
                security_collection.insert_one(security_data)
                log_security_event("SECURITY_ADDED", current_user.username, f"RFID: {security_data['security_rfid']}")
                flash("✅ Security personnel added successfully!", "success")
        
        elif action == "delete":
            security_rfid = request.form.get("security_rfid")
            result = security_collection.delete_one({"security_rfid": security_rfid})
            if result.deleted_count > 0:
                log_security_event("SECURITY_DELETED", current_user.username, f"RFID: {security_rfid}")
                flash("✅ Security personnel deleted successfully!", "success")
            else:
                flash("❌ Security personnel not found!", "danger")
    
    # Get all security personnel
    security_list = list(security_collection.find().sort("name", 1))
    
    return render_template("super_admin/manage_security.html", 
                         security_list=security_list, 
                         user=current_user)

@app.route("/super_admin/users", methods=["GET", "POST"])
@login_required
def manage_users():
    """Manage System Users"""
    if not current_user.is_super_admin():
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

if __name__ == "__main__":
    app.run(debug=True)
