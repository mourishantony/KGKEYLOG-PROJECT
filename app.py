from flask import Flask, render_template, request, redirect, url_for, flash
from datetime import datetime, timedelta
from pymongo import MongoClient
import smtplib
import threading
import time

client = MongoClient("mongodb://localhost:27017/")
db1 = client["user_database"]
db2 = client["key_log_database"]

users_collection = db1["users"]
staff_collection = db2["staff"]
lab_collection = db2["labs"]
temp_logs = db2["temp_logs"]  # Temporary table
permanent_logs = db2["permanent_logs"]  # Permanent table

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Email Configuration
EMAIL_SENDER = "mourishantonyc@gmail.com"
EMAIL_PASSWORD = "hmxn wppp myla mhkc"
WATCHMAN_EMAIL = "rajmourishantony@gmail.com"
CHIEF_AUTHORITY_EMAIL = "jenifercharles29@gmail.com"

# Adjustable Time Limits (seconds)
TIME_LIMIT_1 = 15  # Time after which an email is sent to the Watchman
TIME_LIMIT_2 = 30  # Time after which an email is sent to the Staff
TIME_LIMIT_3 = 60  # Time after which an email is sent to the Chief Authority

# Function to send emails
def send_email(to_email, subject, message):
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            email_message = f"Subject: {subject}\n\n{message}"
            server.sendmail(EMAIL_SENDER, to_email, email_message)
        print(f"Email sent to {to_email}")
    except Exception as e:
        print(f"Error sending email: {e}")

# Function to monitor key return time
def monitor_key_return(staff_rfid, lab_rfid, staff_name, lab_name, staff_email):
    """
    Monitors the return of the lab key. Sends escalating email alerts if the key is not returned within the specified time.
    """

    # Retrieve the key's taken time
    entry = temp_logs.find_one({"staff_rfid": staff_rfid, "lab_rfid": lab_rfid})
    if not entry:
        return  # Exit if key is already returned

    taken_time = entry["taken_at"]  # Get the time when the key was taken

    time.sleep(TIME_LIMIT_1)  # Wait for the first threshold
    
    entry = temp_logs.find_one({"staff_rfid": staff_rfid, "lab_rfid": lab_rfid})
    if entry:
        send_email(WATCHMAN_EMAIL, "Key Return Delay Alert",
                   f"{staff_name} has not returned the key for {lab_name} within {TIME_LIMIT_1} seconds.\n"
                   f"Key Taken At: {taken_time}")

    time.sleep(TIME_LIMIT_2 - TIME_LIMIT_1)  # Wait until the second threshold

    entry = temp_logs.find_one({"staff_rfid": staff_rfid, "lab_rfid": lab_rfid})
    if entry:
        send_email(staff_email, "Key Return Reminder",
                   f"Dear {staff_name}, please return the key for {lab_name} immediately.\n"
                   f"Key Taken At: {taken_time}")

    time.sleep(TIME_LIMIT_3 - TIME_LIMIT_2)  # Wait until the final threshold

    entry = temp_logs.find_one({"staff_rfid": staff_rfid, "lab_rfid": lab_rfid})
    if entry:
        send_email(CHIEF_AUTHORITY_EMAIL, "Key Return Escalation",
                   f"{staff_name} has still not returned the key for {lab_name}. Immediate action required!\n"
                   f"Key Taken At: {taken_time}")
        
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = users_collection.find_one({"username": username, "password": password})
        if user:
            return redirect(url_for("home"))
        else:
            flash("Invalid credentials!", "danger")
    return render_template("login.html")

@app.route("/home", methods=["GET", "POST"])
def home():
    message = ""
    if request.method == "POST":
        staff_rfid = request.form["staff_rfid"]
        lab_rfid = request.form["lab_rfid"]

        staff = staff_collection.find_one({"staff_rfid": staff_rfid})
        lab = lab_collection.find_one({"lab_rfid": lab_rfid})

        if not staff:
            message = "Invalid Staff RFID!"
        elif not lab:
            message = "Invalid Lab RFID!"
        else:
            existing_entry = temp_logs.find_one({"lab_rfid": lab_rfid})

            if existing_entry:
                if existing_entry["staff_rfid"] == staff_rfid:
                    # Remove from temp_logs and update permanent_logs as returned
                    temp_logs.delete_one({"lab_rfid": lab_rfid})
                    permanent_logs.update_one(
                        {"staff_rfid": staff_rfid, "lab_rfid": lab_rfid, "status": "taken"},
                        {"$set": {"status": "returned", "returned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}}
                    )
                    message = f"Key for {lab['lab_name']} has been returned by {staff['name']}."
                else:
                    message = f"Key for {lab['lab_name']} is already taken by {existing_entry['staff_name']}."
            else:
                # Insert into temp_logs (active keys)
                temp_logs.insert_one({
                    "staff_rfid": staff_rfid,
                    "staff_name": staff["name"],
                    "lab_rfid": lab_rfid,
                    "lab_name": lab["lab_name"],
                    "taken_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })

                # Insert into permanent_logs (history table)
                permanent_logs.insert_one({
                    "staff_rfid": staff_rfid,
                    "staff_name": staff["name"],
                    "lab_rfid": lab_rfid,
                    "lab_name": lab["lab_name"],
                    "taken_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "status": "taken"
                })

                # Start the monitoring thread
                threading.Thread(target=monitor_key_return, args=(
                    staff_rfid, lab_rfid, staff["name"], lab["lab_name"], staff["email"]
                )).start()

                message = f"{staff['name']} has taken the key for {lab['lab_name']}."

    return render_template("home.html", message=message)

@app.route("/database")
def database():
    logs = permanent_logs.find()
    return render_template("database.html", logs=logs)

if __name__ == "__main__":
    app.run(debug=True)
