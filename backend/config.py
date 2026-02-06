import os
import secrets

class Config:
    # Generate secure key: python -c "import secrets; print(secrets.token_hex(32))"
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///documents.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or 'uploads'
    ENCRYPTED_FOLDER = os.environ.get('ENCRYPTED_FOLDER') or 'encrypted_files'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # Security settings
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    TESTING = os.environ.get('FLASK_TESTING', 'False').lower() == 'true'
    
    @staticmethod
    def init_app(app):
        """Initialize application with security checks"""
        # Warn if using default secret key in production
        if not os.environ.get('SECRET_KEY') and not Config.DEBUG:
            print("⚠️  WARNING: Using auto-generated SECRET_KEY. Set SECRET_KEY environment variable for production!")