from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")

# Select the database and collection
db2 = client["key_log_database"]
staff_collection = db2["staff"]

db1 = client["user_database"]
db2 = client["key_log_database"]

users_collection = db1["users"]
staff_collection = db2["staff"]
lab_collection = db2["labs"]
temp_logs = db2["temp_logs"]
permanent_logs = db2["permanent_logs"]
security_collection = db2["security"]

# Delete all staff records
staff_collection.delete_many({})

print("Staff collection cleared successfully! Now re-run seed_db.py")
