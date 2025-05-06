from pymongo import MongoClient


# Database for Users
client = MongoClient("mongodb://localhost:27017/")
db = client["user_database"]

users_collection = db["users"]
staff_collection = db["staff"]
lab_collection = db["labs"]
temp_logs = db["temp_logs"]
permanent_logs = db["permanent_logs"]
security_collection = db["security"]

# Insert sample users
users_collection.insert_many([
    {"username": "admin", "password": "123"},
    {"username": "user1", "password": "pass123"}
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
