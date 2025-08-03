from flask_login import UserMixin
from pymongo import MongoClient
from datetime import datetime

class User(UserMixin):
    def __init__(self, username, password=None, email=None, role='user', created_at=None, is_active=True):
        self.username = username
        self.password = password
        self.email = email
        self.role = role
        self.created_at = created_at or datetime.now()
        self.is_active = is_active
        
    def get_id(self):
        """Required by Flask-Login - returns unique identifier"""
        return self.username
    
    def is_authenticated(self):
        """Returns True if user is authenticated"""
        return True
    
    def is_active(self):
        """Returns True if user is active"""
        return self.is_active
    
    def is_anonymous(self):
        """Returns False for regular users"""
        return False
    
    @staticmethod
    def get(username, db):
        """Get user from database"""
        user_data = db.users_collection.find_one({"username": username})
        if user_data:
            return User(
                username=user_data['username'],
                password=user_data['password'],
                email=user_data.get('email'),
                role=user_data.get('role', 'user'),
                created_at=user_data.get('created_at'),
                is_active=user_data.get('is_active', True)
            )
        return None
    
    def check_password(self, password):
        """Check if provided password matches"""
        return self.password == password  # In production, use hashed passwords!
    
    def is_admin(self):
        """Check if user is admin or super_admin"""
        return self.role in ['admin', 'super_admin']
    
    def is_super_admin(self):
        """Check if user is super_admin"""
        return self.role == 'super_admin'
    
    def can_manage_rfid(self):
        """Check if user can manage RFID data"""
        return self.role == 'super_admin'
    
    def can_view_database(self):
        """Check if user can view database"""
        return self.role in ['admin', 'super_admin']
