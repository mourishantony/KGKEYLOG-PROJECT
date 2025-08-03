import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
     # Rate Limiting - Development
    RATELIMIT_STORAGE_URL = "memory://"
    RATELIMIT_ENABLED = True
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'fallback-secret-key'
    
    # Database Configuration
    MONGODB_URI = os.environ.get('MONGODB_URI') or 'mongodb://localhost:27017/'
    DATABASE_NAME = os.environ.get('DATABASE_NAME') or 'user_database'
    
    # Email Configuration
    EMAIL_SENDER = os.environ.get('EMAIL_SENDER')
    EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD')
    WATCHMAN_EMAIL = os.environ.get('WATCHMAN_EMAIL')
    CHIEF_AUTHORITY_EMAIL = os.environ.get('CHIEF_AUTHORITY_EMAIL')
    
    # Time Limits
    TIME_LIMIT_1 = int(os.environ.get('TIME_LIMIT_1', 15))
    TIME_LIMIT_2 = int(os.environ.get('TIME_LIMIT_2', 30))
    TIME_LIMIT_3 = int(os.environ.get('TIME_LIMIT_3', 60))
    
    # Session Security
    SESSION_COOKIE_SECURE = True  # Enable in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes
    REMEMBER_COOKIE_DURATION = 86400  # 1 day
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True

    # CSRF Protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour
    
    # User Roles
    USER_ROLES = ['user', 'admin', 'super_admin']
    # Additional Security Headers
    SEND_FILE_MAX_AGE_DEFAULT = 31536000  # 1 year for static files