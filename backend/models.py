from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timezone, timedelta

db = SQLAlchemy()

# IST timezone (UTC+5:30)
IST = timezone(timedelta(hours=5, minutes=30))

def get_ist_now():
    return datetime.now(IST)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # admin, editor, viewer
    created_at = db.Column(db.DateTime, default=get_ist_now)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    original_filename = db.Column(db.String(200), nullable=False)
    encrypted_path = db.Column(db.String(300), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    upload_date = db.Column(db.DateTime, default=get_ist_now)
    file_type = db.Column(db.String(50))
    file_size = db.Column(db.Integer)
    file_hash = db.Column(db.String(64))  # SHA-256 hash for integrity
    idempotency_key = db.Column(db.String(64), unique=True, index=True)  # Prevents duplicate uploads
    
class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=True)
    action = db.Column(db.String(50), nullable=False)  # upload, download, view, share
    timestamp = db.Column(db.DateTime, default=get_ist_now)
    ip_address = db.Column(db.String(50))

class DocumentPermission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    permission = db.Column(db.String(20), nullable=False)  # view, edit
    granted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    granted_at = db.Column(db.DateTime, default=get_ist_now)
    
    __table_args__ = (db.UniqueConstraint('document_id', 'user_id', name='unique_doc_user_permission'),)

class DocumentVersion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=False)
    version_number = db.Column(db.Integer, nullable=False)
    encrypted_path = db.Column(db.String(300), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=get_ist_now)
    file_size = db.Column(db.Integer)
    file_hash = db.Column(db.String(64))  # SHA-256 hash for version integrity
    change_description = db.Column(db.String(255))

class ShareLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    download_limit = db.Column(db.Integer, default=None)  # None = unlimited
    download_count = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=get_ist_now)