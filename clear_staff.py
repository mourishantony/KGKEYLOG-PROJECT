from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")

# Select the database and collection
db2 = client["key_log_database"]
staff_collection = db2["staff"]

# Delete all staff records
staff_collection.delete_many({})

print("Staff collection cleared successfully! Now re-run seed_db.py")
