from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")

# Database 1 (Users)
db1 = client["user_database"]
users_collection = db1["users"]

# Database 2 (RFID and Logs)
db2 = client["key_log_database"]
staff_collection = db2["staff"]
lab_collection = db2["labs"]
logs_collection = db2["logs"]

# Insert sample users
users_collection.insert_many([
    {"username": "admin", "password": "123"},
    {"username": "user1", "password": "pass123"}
])

# Insert sample staff RFIDs
staff_collection.insert_many([
    {"staff_rfid": "201", "name": "Mourish"},
    {"staff_rfid": "123", "name": "Joe "}
])

# Insert sample lab RFIDs
lab_collection.insert_many([
    {"lab_rfid": "1234", "lab_name": "210 Lab"},
    {"lab_rfid": "12345", "lab_name": "Computer Lab"}
])

print("Database seeded successfully!")
