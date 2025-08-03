from pymongo import MongoClient
from datetime import datetime

# Database Connection
client = MongoClient("mongodb://localhost:27017/")
db = client["user_database"]

# Collections
users_collection = db["users"]
staff_collection = db["staff"]
lab_collection = db["labs"]
temp_logs = db["temp_logs"]
permanent_logs = db["permanent_logs"]
security_collection = db["security"]

def seed_admins_only():
    """Seed only admin users - RFID data will be managed via super admin panel"""
    
    print("🧹 Clearing existing admin users...")
    users_collection.delete_many({})
    
    print("👑 Creating admin users...")
    admin_users = [
        {
            "username": "super_admin",
            "password": "super123",  # Change this!
            "email": "superadmin@kgkite.ac.in",
            "role": "super_admin",
            "created_at": datetime.now(),
            "is_active": True
        },
        {
            "username": "admin",
            "password": "admin123",  # Change this!
            "email": "admin@kgkite.ac.in",
            "role": "admin", 
            "created_at": datetime.now(),
            "is_active": True
        },
        {
            "username": "user1",
            "password": "user123",
            "email": "user1@kgkite.ac.in",
            "role": "user",
            "created_at": datetime.now(),
            "is_active": True
        }
    ]
    
    users_collection.insert_many(admin_users)
    print(f"✅ Created {len(admin_users)} admin users")
    
    # Clear other collections (will be managed via super admin panel)
    print("🧹 Clearing RFID collections (will be managed via Super Admin panel)...")
    staff_collection.delete_many({})
    lab_collection.delete_many({})
    security_collection.delete_many({})
    temp_logs.delete_many({})
    
    # Keep permanent logs for historical data
    print("📊 Permanent logs preserved for historical data")
    
    # Create indexes for better performance
    print("🚀 Creating database indexes...")
    
    # User collection indexes
    users_collection.create_index("username", unique=True)
    users_collection.create_index("email")
    users_collection.create_index("role")
    
    # Staff collection indexes
    staff_collection.create_index("staff_rfid", unique=True)
    staff_collection.create_index("email")
    
    # Lab collection indexes
    lab_collection.create_index("lab_rfid", unique=True)
    lab_collection.create_index("lab_name")
    
    # Security collection indexes
    security_collection.create_index("security_rfid", unique=True)
    
    # Log collection indexes
    temp_logs.create_index("lab_rfid")
    temp_logs.create_index("staff_rfid")
    temp_logs.create_index("taken_at")
    
    permanent_logs.create_index("staff_rfid")
    permanent_logs.create_index("lab_rfid")
    permanent_logs.create_index("taken_at")
    permanent_logs.create_index("status")
    
    print("✅ Database indexes created successfully!")
    
    print("\n🎉 Enhanced Database Setup Complete!")
    print("\n👑 Super Admin Login Details:")
    print("   Username: super_admin")
    print("   Password: super123")
    print("\n🔧 Admin Login Details:")
    print("   Username: admin") 
    print("   Password: admin123")
    print("\n👤 User Login Details:")
    print("   Username: user1")
    print("   Password: user123")
    print("\n IMPORTANT: Change default passwords in production!")
    print("\n🎯 Next Steps:")
    print("   1. Login as super_admin")
    print("   2. Go to Super Admin Panel (/super_admin)")
    print("   3. Add Staff, Labs, and Security RFID data")

if __name__ == "__main__":
    seed_admins_only()
