from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from datetime import datetime, timedelta
from pymongo import MongoClient
import smtplib
import threading
import time

# MongoDB Connection
client = MongoClient("mongodb://localhost:27017/")
db = client["user_database"]

users_collection = db["users"]
staff_collection = db["staff"]
lab_collection = db["labs"]
temp_logs = db["temp_logs"]
permanent_logs = db["permanent_logs"]
security_collection = db["security"]

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Email Configuration
EMAIL_SENDER = "mourishantonyc@gmail.com"
EMAIL_PASSWORD = "hmxn wppp myla mhkc"
WATCHMAN_EMAIL = "rajmourishantony@gmail.com"
CHIEF_AUTHORITY_EMAIL = "jenifercharles29@gmail.com"

# Adjustable Time Limits (seconds)
TIME_LIMIT_1 = 15
TIME_LIMIT_2 = 30
TIME_LIMIT_3 = 60

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
def login():
    """Login page."""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = users_collection.find_one({"username": username, "password": password})
        if user:
            session["username"] = username
            return redirect(url_for("home"))
        else:
            flash("❌ Invalid credentials!", "danger")
    return render_template("login.html")

@app.route("/home", methods=["GET", "POST"])
def home():
    """Home page."""
    if "username" not in session:
        return redirect(url_for("login"))

    message = ""

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

    return render_template("home.html", message=message)


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
    app.run(debug=True)
