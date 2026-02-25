from flask_login import UserMixin
from pymongo import MongoClient
from datetime import datetime

class User(UserMixin):
    def __init__(self, username, password=None, email=None, role='security', 
                 created_at=None, is_active=True, department=None, permissions=None):
        self.username = username
        self.password = password
        self.email = email
        self.role = role
        self.created_at = created_at or datetime.now()
        self.is_active = is_active
        self.department = department  # For HODs
        self.permissions = permissions or []
        
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
                role=user_data.get('role', 'security'),
                created_at=user_data.get('created_at'),
                is_active=user_data.get('is_active', True),
                department=user_data.get('department'),
                permissions=user_data.get('permissions', [])
            )
        return None
    
    def check_password(self, password):
        """Check if provided password matches"""
        return self.password == password
    
    def is_super_admin(self):
        """Check if user is super_admin"""
        return self.role == 'super_admin'
    
    def is_security(self):
        """Check if user is security personnel"""
        return self.role == 'security'
    
    def can_access_home(self):
        """Check if user can access home page (key management)"""
        return self.role in ['super_admin', 'security']
    
    def can_view_database(self):
        """Check if user can view database"""
        return self.role in ['super_admin', 'security', 'dean', 'principal', 'head_security']
    
    def can_view_department_only(self):
        """Check if user can only view their department"""
        return self.role == 'hod'
    
    def should_receive_notifications(self):
        """Check if user should receive email notifications"""
        return self.role in ['hod', 'dean', 'principal', 'head_security']
    
    def get_notification_level(self):
        """Get the escalation level for notifications"""
        levels = {
            'security': 1,
            'hod': 2,
            'head_security': 3,
            'dean': 4,
            'principal': 5
        }
        return levels.get(self.role, 0)
    def is_admin(self):
        """Check if user is admin or super_admin"""
        return self.role in ['admin', 'super_admin']

    def can_view_database(self):
        """Check if user can view database"""
        return self.role in ['super_admin', 'admin', 'security', 'dean', 'principal', 'head_security']
