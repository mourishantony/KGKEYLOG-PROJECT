from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()

# Database Connection (supports both local and Atlas)
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

# Delete all staff records
staff_collection.delete_many({})

print("Staff collection cleared successfully! Now re-run seed_db.py")
