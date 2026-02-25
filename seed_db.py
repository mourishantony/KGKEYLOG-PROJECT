from pymongo import MongoClient
from werkzeug.security import generate_password_hash
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

# Clear existing data before seeding
users_collection.delete_many({})
staff_collection.delete_many({})
lab_collection.delete_many({})
security_collection.delete_many({})

# Insert sample users (with hashed passwords and roles)
users_collection.insert_many([
    {"username": "admin", "password": generate_password_hash("123"), "role": "admin"},
    {"username": "user1", "password": generate_password_hash("pass123"), "role": "user"}
])

# Insert sample staff RFIDs with emails
staff_collection.insert_many([
    {"staff_rfid": "0000808798", "name": "JOE DANIEL", "email": "joedanielajd@gmail.com"},
    {"staff_rfid": "0000806285", "name": "Mourish Antony", "email": "24uad201mourish@kgkite.ac.in"},
    {"staff_rfid": "999", "name": "JOHN", "email": "godtrap144@gmail.com"}
])

# Insert sample lab RFIDs
lab_collection.insert_many([
    {"lab_rfid": "0011762700", "lab_name": "210 Lab"},
    {"lab_rfid": "12345", "lab_name": "Computer Lab"}
])

# Insert sample security personnel
security_collection.insert_many([
    {"security_rfid": "0011764138", "name": "JOHNY", "email": "joedaniel1906@gmail.com"},
    {"security_rfid": "302", "name": "Michael", "email": "security2@kgkite.ac.in"}
])

print("Database seeded successfully!")
