from flask import Flask, render_template, request, redirect, url_for, flash
from datetime import datetime
from pymongo import MongoClient

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

                message = f"{staff['name']} has taken the key for {lab['lab_name']}."

    return render_template("home.html", message=message)

@app.route("/database")
def database():
    logs = permanent_logs.find()
    return render_template("database.html", logs=logs)

if __name__ == "__main__":
    app.run(debug=True)
