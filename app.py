from flask import Flask, render_template, request, redirect, url_for, flash
from datetime import datetime
from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db1 = client["user_database"]  # Database for users
db2 = client["key_log_database"]  # Database for RFID logs

users_collection = db1["users"]
staff_collection = db2["staff"]
lab_collection = db2["labs"]
logs_collection = db2["logs"]

app = Flask(__name__)
app.secret_key = "your_secret_key"

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

        # Fetch staff and lab details from database
        staff = staff_collection.find_one({"staff_rfid": staff_rfid})
        lab = lab_collection.find_one({"lab_rfid": lab_rfid})

        if not staff:
            message = "Invalid Staff RFID!"
        elif not lab:
            message = "Invalid Lab RFID!"
        else:
            existing_entry = logs_collection.find_one({"lab_rfid": lab_rfid})

            if existing_entry:
                if existing_entry["staff_rfid"] == staff_rfid:
                    logs_collection.delete_one({"lab_rfid": lab_rfid})
                    message = f"Key for {lab['lab_name']} has been returned by {staff['name']}."
                else:
                    message = f"Key for {lab['lab_name']} is already taken by {existing_entry['staff_name']}."
            else:
                logs_collection.insert_one({
                    "staff_rfid": staff_rfid,
                    "staff_name": staff["name"],
                    "lab_rfid": lab_rfid,
                    "lab_name": lab["lab_name"],
                    "taken_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
                message = f"{staff['name']} has taken the key for {lab['lab_name']}."

    return render_template("home.html", message=message)

@app.route("/database")
def database():
    logs = logs_collection.find()
    return render_template("database.html", logs=logs)

if __name__ == "__main__":
    app.run(debug=True)
