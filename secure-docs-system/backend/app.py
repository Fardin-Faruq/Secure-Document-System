from flask import Flask, request, jsonify, send_file, redirect
from flask_cors import CORS
from flask_login import LoginManager
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from config import Config
from models import db, User, Document, AccessLog, DocumentPermission, DocumentVersion, ShareLink
from encryption import DocumentEncryption
import jwt
from datetime import datetime, timedelta, timezone
from functools import wraps
import os
import uuid
import secrets
from io import BytesIO
import hashlib  # ✅ ADD THIS

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
CORS(app, supports_credentials=True)
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)

# Initialize encryption
encryption = DocumentEncryption(app.config['SECRET_KEY'])

# Create upload folders if they don't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['ENCRYPTED_FOLDER'], exist_ok=True)

# ✅ HTTPS Enforcement middleware
@app.before_request
def enforce_https():
    """
    Redirect HTTP requests to HTTPS in production.
    Disabled in DEBUG mode and for localhost/127.0.0.1.
    """
    if not app.config['DEBUG']:
        # Allow localhost and 127.0.0.1 to use HTTP
        if request.host.startswith(('localhost', '127.0.0.1')):
            return None
        
        # Check if request is using HTTP
        if request.scheme == 'http':
            url = request.url.replace('http://', 'https://', 1)
            return redirect(url, code=301)
        
        # Check for secure headers from reverse proxy (e.g., nginx, CloudFlare)
        if request.headers.get('X-Forwarded-Proto', 'http') == 'http':
            url = request.url.replace('http://', 'https://', 1)
            return redirect(url, code=301)
    elif request.scheme == 'http' and not request.path.startswith('/api/test'):
        app.logger.warning(f"⚠️  Insecure HTTP request to {request.path} (OK in DEBUG mode)")

# ✅ Security headers middleware
@app.after_request
def set_security_headers(response):
    """Add security headers to all responses"""
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Enable XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Strict Transport Security (HSTS) - only in production
    if not app.config['DEBUG']:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Content Security Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' data:;"
    )
    
    return response

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png', 'xlsx', 'csv'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ✅ ADD THIS NEW FUNCTION (after allowed_file)
def calculate_file_hash(file_data):
    """Calculate SHA-256 hash of file data for integrity verification"""
    return hashlib.sha256(file_data).hexdigest()

def verify_file_integrity(file_data, expected_hash):
    """Verify file integrity by comparing hashes"""
    actual_hash = calculate_file_hash(file_data)
    return actual_hash == expected_hash

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# JWT token decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
            
            if not current_user:
                return jsonify({'message': 'User not found!'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# Role-based access control decorator
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(current_user, *args, **kwargs):
            if current_user.role not in roles:
                return jsonify({'message': 'Insufficient permissions!'}), 403
            return f(current_user, *args, **kwargs)
        return decorated_function
    return decorator

# Helper function to check document permission
def check_document_permission(user, document, permission='view'):
    """Check if user has permission to access document"""
    # Admin can access everything
    if user.role == 'admin':
        return True
    
    # Document owner can access their own documents
    if document.uploaded_by == user.id:
        return True
    
    # For view permission: editors and viewers can view all documents by default
    if permission == 'view':
        if user.role in ['editor', 'viewer']:
            return True
    
    # Check explicit permissions (for more restrictive access control)
    perm = DocumentPermission.query.filter_by(
        document_id=document.id,
        user_id=user.id
    ).first()
    
    if perm:
        # 'edit' permission implies 'view' permission
        if permission == 'view':
            return perm.permission in ['view', 'edit']
        elif permission == 'edit':
            return perm.permission == 'edit'
    
    # Default deny for edit operations if no permission granted
    return False

# Helper function to log access
def log_access(user_id, document_id, action, ip_address):
    """Log document access"""
    try:
        log = AccessLog(
            user_id=user_id,
            document_id=document_id,
            action=action,
            ip_address=ip_address
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        pass  # Log failures should not break the main operation

# Routes
@app.route('/api/test', methods=['GET'])
def test():
    return jsonify({"message": "Backend is working!"})

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        username = data.get('username')
        password = data.get('password')
        role = data.get('role', 'viewer')
        
        if not username or not password:
            return jsonify({'message': 'Username and password are required!'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'message': 'User already exists!'}), 400
        
        if role not in ['admin', 'editor', 'viewer']:
            return jsonify({'message': 'Invalid role!'}), 400
        
        password_hash = generate_password_hash(password)
        new_user = User(username=username, password_hash=password_hash, role=role)
        
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({
            'message': 'User registered successfully!',
            'user': {
                'id': new_user.id,
                'username': new_user.username,
                'role': new_user.role
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'message': 'Username and password are required!'}), 400
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({'message': 'Invalid username or password!'}), 401
        
        # ✅ FIX: JWT requires UNIX timestamp (int), not datetime object
        exp_time = datetime.now(timezone.utc) + timedelta(hours=24)
        exp_timestamp = int(exp_time.timestamp())
        
        token = jwt.encode({
            'user_id': user.id,
            'username': user.username,
            'role': user.role,
            'exp': exp_timestamp
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({
            'message': 'Login successful!',
            'token': token,
            'user': {
                'id': user.id,
                'username': user.username,
                'role': user.role
            }
        }), 200
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/verify', methods=['GET'])
@token_required
def verify_token(current_user):
    return jsonify({
        'valid': True,
        'user': {
            'id': current_user.id,
            'username': current_user.username,
            'role': current_user.role
        }
    }), 200

@app.route('/api/users', methods=['GET'])
@token_required
@role_required('admin')
def get_users(current_user):
    users = User.query.all()
    return jsonify({
        'users': [{
            'id': user.id,
            'username': user.username,
            'role': user.role,
            'created_at': user.created_at.isoformat()
        } for user in users]
    }), 200

# Document Upload
@app.route('/api/documents/upload', methods=['POST'])
@token_required
@role_required('admin', 'editor')
def upload_document(current_user):
    try:
        # ✅ Check for idempotency key (prevents duplicate uploads from retries)
        idempotency_key = request.headers.get('X-Idempotency-Key')
        
        if idempotency_key:
            # Check if this request was already processed
            existing_doc = Document.query.filter_by(
                idempotency_key=idempotency_key
            ).first()
            
            if existing_doc:
                # Return existing document (idempotent response)
                return jsonify({
                    'message': 'File already uploaded (duplicate request detected)',
                    'document': {
                        'id': existing_doc.id,
                        'filename': existing_doc.original_filename,
                        'file_type': existing_doc.file_type,
                        'file_size': existing_doc.file_size,
                        'upload_date': existing_doc.upload_date.isoformat()
                    },
                    'idempotent': True
                }), 200
        
        if 'file' not in request.files:
            return jsonify({'message': 'No file provided!'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'message': 'No file selected!'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'message': 'File type not allowed!'}), 400
        
        # Generate unique filename
        original_filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{original_filename}"
        
        # Read and encrypt file
        # Read file data
        file_data = file.read()
        
        # ✅ Calculate integrity hash BEFORE encryption
        file_hash = calculate_file_hash(file_data)
        
        # Encrypt file
        encrypted_data = encryption.encrypt_file(file_data)
        
        # Save encrypted file
        encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], unique_filename)
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Create database record with hash and idempotency key
        document = Document(
            filename=unique_filename,
            original_filename=original_filename,
            encrypted_path=encrypted_path,
            uploaded_by=current_user.id,
            file_type=original_filename.rsplit('.', 1)[1].lower(),
            file_size=len(file_data),
            file_hash=file_hash,
            idempotency_key=idempotency_key  # ✅ ADD THIS
        )
        
        db.session.add(document)
        db.session.flush()  # Assign ID to document without committing
        
        # Create initial version with hash
        version = DocumentVersion(
            document_id=document.id,
            version_number=1,
            encrypted_path=encrypted_path,
            uploaded_by=current_user.id,
            file_size=len(file_data),
            file_hash=file_hash,  # ✅ ADD THIS
            change_description='Initial upload'
        )
        db.session.add(version)
        
        # Log the upload action
        log = AccessLog(
            user_id=current_user.id,
            document_id=document.id,
            action='upload',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            'message': 'File uploaded successfully!',
            'document': {
                'id': document.id,
                'filename': document.original_filename,
                'file_type': document.file_type,
                'file_size': document.file_size,
                'upload_date': document.upload_date.isoformat()
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Get all documents
@app.route('/api/documents', methods=['GET'])
@token_required
def get_documents(current_user):
    try:
        documents = Document.query.all()
        
        return jsonify({
            'documents': [{
                'id': doc.id,
                'filename': doc.original_filename,
                'file_type': doc.file_type,
                'file_size': doc.file_size,
                'uploaded_by': User.query.get(doc.uploaded_by).username,
                'uploaded_by_id': doc.uploaded_by,
                'upload_date': doc.upload_date.isoformat()
            } for doc in documents]
        }), 200
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Download document
@app.route('/api/documents/<int:document_id>/download', methods=['GET'])
@token_required
def download_document(current_user, document_id):
    try:
        document = Document.query.get(document_id)
        
        if not document:
            return jsonify({'message': 'Document not found!'}), 404
        
        # ✅ FIX: Add permission check
        if not check_document_permission(current_user, document, 'view'):
            return jsonify({'message': 'Access denied!'}), 403
        
        # Read encrypted file
        # Read encrypted file
        with open(document.encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Decrypt file
        decrypted_data = encryption.decrypt_file(encrypted_data)
        
        # ✅ Verify file integrity (detect tampering)
        if document.file_hash:
            if not verify_file_integrity(decrypted_data, document.file_hash):
                # Log security incident
                log = AccessLog(
                    user_id=current_user.id,
                    document_id=document.id,
                    action='integrity_failure',
                    ip_address=request.remote_addr
                )
                db.session.add(log)
                db.session.commit()
                
                return jsonify({
                    'message': 'ERROR: File integrity check failed! Document may have been tampered with.',
                    'error': 'INTEGRITY_VIOLATION'
                }), 500
        
        # Log the download action
        log = AccessLog(
            user_id=current_user.id,
            document_id=document.id,
            action='download',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        # ✅ FIX: Use BytesIO to stream from memory (no temp files)
        file_stream = BytesIO(decrypted_data)
        
        return send_file(
            file_stream,
            as_attachment=True,
            download_name=document.original_filename,
            mimetype='application/octet-stream'
        )
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Grant document permission
@app.route('/api/documents/<int:document_id>/permissions', methods=['POST'])
@token_required
def grant_permission(current_user, document_id):
    try:
        document = Document.query.get(document_id)
        
        if not document:
            return jsonify({'message': 'Document not found!'}), 404
        
        # Only document owner or admin can grant permissions
        if document.uploaded_by != current_user.id and current_user.role != 'admin':
            return jsonify({'message': 'Only document owner or admin can grant permissions!'}), 403
        
        data = request.get_json()
        user_id = data.get('user_id')
        permission = data.get('permission', 'view')  # view or edit
        
        if permission not in ['view', 'edit']:
            return jsonify({'message': 'Invalid permission type!'}), 400
        
        # Check if user exists
        user = User.query.get(user_id)
        if not user:
            return jsonify({'message': 'User not found!'}), 404
        
        # Check if permission already exists
        existing_perm = DocumentPermission.query.filter_by(
            document_id=document_id,
            user_id=user_id
        ).first()
        
        if existing_perm:
            existing_perm.permission = permission
        else:
            perm = DocumentPermission(
                document_id=document_id,
                user_id=user_id,
                permission=permission,
                granted_by=current_user.id
            )
            db.session.add(perm)
        
        db.session.commit()
        
        return jsonify({'message': f'Permission granted: {permission}!'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Revoke document permission
@app.route('/api/documents/<int:document_id>/permissions/<int:user_id>', methods=['DELETE'])
@token_required
def revoke_permission(current_user, document_id, user_id):
    try:
        document = Document.query.get(document_id)
        
        if not document:
            return jsonify({'message': 'Document not found!'}), 404
        
        # Only document owner or admin can revoke permissions
        if document.uploaded_by != current_user.id and current_user.role != 'admin':
            return jsonify({'message': 'Only document owner or admin can revoke permissions!'}), 403
        
        perm = DocumentPermission.query.filter_by(
            document_id=document_id,
            user_id=user_id
        ).first()
        
        if not perm:
            return jsonify({'message': 'Permission not found!'}), 404
        
        db.session.delete(perm)
        db.session.commit()
        
        return jsonify({'message': 'Permission revoked!'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Get document permissions
@app.route('/api/documents/<int:document_id>/permissions', methods=['GET'])
@token_required
def get_permissions(current_user, document_id):
    try:
        document = Document.query.get(document_id)
        
        if not document:
            return jsonify({'message': 'Document not found!'}), 404
        
        # Only document owner or admin can view permissions
        if document.uploaded_by != current_user.id and current_user.role != 'admin':
            return jsonify({'message': 'Only document owner or admin can view permissions!'}), 403
        
        perms = DocumentPermission.query.filter_by(document_id=document_id).all()
        
        return jsonify({
            'permissions': [{
                'id': perm.id,
                'user_id': perm.user_id,
                'username': User.query.get(perm.user_id).username,
                'permission': perm.permission,
                'granted_by': User.query.get(perm.granted_by).username,
                'granted_at': perm.granted_at.isoformat()
            } for perm in perms]
        }), 200
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Get document versions
@app.route('/api/documents/<int:document_id>/versions', methods=['GET'])
@token_required
def get_versions(current_user, document_id):
    try:
        document = Document.query.get(document_id)
        
        if not document:
            return jsonify({'message': 'Document not found!'}), 404
        
        # Check permission
        if not check_document_permission(current_user, document, 'view'):
            return jsonify({'message': 'Access denied!'}), 403
        
        versions = DocumentVersion.query.filter_by(document_id=document_id).order_by(
            DocumentVersion.version_number.desc()
        ).all()
        
        return jsonify({
            'versions': [{
                'id': ver.id,
                'version_number': ver.version_number,
                'uploaded_by': User.query.get(ver.uploaded_by).username,
                'created_at': ver.created_at.isoformat(),
                'file_size': ver.file_size,
                'change_description': ver.change_description
            } for ver in versions]
        }), 200
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Update document (create new version)
@app.route('/api/documents/<int:document_id>/update', methods=['POST'])
@token_required
@role_required('admin', 'editor')
def update_document(current_user, document_id):
    try:
        document = Document.query.get(document_id)
        
        if not document:
            return jsonify({'message': 'Document not found!'}), 404
        
        # Only document owner or admin can update
        if document.uploaded_by != current_user.id and current_user.role != 'admin':
            return jsonify({'message': 'Only document owner or admin can update!'}), 403
        
        if 'file' not in request.files:
            return jsonify({'message': 'No file provided!'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'message': 'No file selected!'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'message': 'File type not allowed!'}), 400
        
        # Read and encrypt new file
        # Read file data
        file_data = file.read()
        
        # ✅ Calculate integrity hash
        file_hash = calculate_file_hash(file_data)
        
        # Encrypt file
        encrypted_data = encryption.encrypt_file(file_data)
        
        # Generate new encrypted filename
        unique_filename = f"{uuid.uuid4()}_{secure_filename(file.filename)}"
        encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], unique_filename)
        
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Get latest version number
        latest_version = DocumentVersion.query.filter_by(
            document_id=document_id
        ).order_by(DocumentVersion.version_number.desc()).first()
        
        new_version_number = (latest_version.version_number + 1) if latest_version else 1
        
        # Create new version with hash
        version = DocumentVersion(
            document_id=document_id,
            version_number=new_version_number,
            encrypted_path=encrypted_path,
            uploaded_by=current_user.id,
            file_size=len(file_data),
            file_hash=file_hash,  # ✅ ADD THIS
            change_description=request.form.get('description', 'Updated version')
        )
        db.session.add(version)
        
        # Update document metadata with hash and IST timestamp
        document.filename = unique_filename
        document.file_size = len(file_data)
        document.file_hash = file_hash
        document.upload_date = datetime.now(timezone(timedelta(hours=5, minutes=30)))
        
        # Log the update
        log = AccessLog(
            user_id=current_user.id,
            document_id=document_id,
            action='update',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            'message': 'Document updated successfully!',
            'version_number': new_version_number
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Rollback document to previous version
@app.route('/api/documents/<int:document_id>/rollback/<int:version_id>', methods=['POST'])
@token_required
def rollback_version(current_user, document_id, version_id):
    try:
        document = Document.query.get(document_id)
        
        if not document:
            return jsonify({'message': 'Document not found!'}), 404
        
        # Only document owner or admin can rollback
        if document.uploaded_by != current_user.id and current_user.role != 'admin':
            return jsonify({'message': 'Only document owner or admin can rollback!'}), 403
        
        version = DocumentVersion.query.get(version_id)
        
        if not version or version.document_id != document_id:
            return jsonify({'message': 'Version not found!'}), 404
        
        # Read encrypted data from old version
        with open(version.encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Create new version from old content
        latest_version = DocumentVersion.query.filter_by(
            document_id=document_id
        ).order_by(DocumentVersion.version_number.desc()).first()
        
        new_version_number = latest_version.version_number + 1
        
        new_version = DocumentVersion(
            document_id=document_id,
            version_number=new_version_number,
            encrypted_path=version.encrypted_path,
            uploaded_by=current_user.id,
            file_size=version.file_size,
            change_description=f'Rollback from version {version.version_number}'
        )
        db.session.add(new_version)
        
        # Log the rollback
        log = AccessLog(
            user_id=current_user.id,
            document_id=document_id,
            action='rollback',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            'message': f'Document rolled back to version {version.version_number}!',
            'new_version_number': new_version_number
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Delete document (admin only)
@app.route('/api/documents/<int:document_id>', methods=['DELETE'])
@token_required
@role_required('admin')
def delete_document(current_user, document_id):
    try:
        document = Document.query.get(document_id)
        
        if not document:
            return jsonify({'message': 'Document not found!'}), 404
        
        # Delete encrypted file
        if os.path.exists(document.encrypted_path):
            os.remove(document.encrypted_path)
        
        # Log the delete action
        log = AccessLog(
            user_id=current_user.id,
            document_id=document.id,
            action='delete',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        
        # Delete database record
        db.session.delete(document)
        db.session.commit()
        
        return jsonify({'message': 'Document deleted successfully!'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Get access logs (admin only)
@app.route('/api/logs', methods=['GET'])
@token_required
@role_required('admin')
def get_logs(current_user):
    try:
        # Get filters from query parameters
        document_id = request.args.get('document_id', type=int)
        action = request.args.get('action')
        user_id = request.args.get('user_id', type=int)
        days = request.args.get('days', default=7, type=int)
        
        query = AccessLog.query
        
        if document_id:
            query = query.filter_by(document_id=document_id)
        
        if action:
            query = query.filter_by(action=action)
        
        if user_id:
            query = query.filter_by(user_id=user_id)
        
        # Filter by date range
        if days:
            start_date = datetime.now(timezone.utc) - timedelta(days=days)
            query = query.filter(AccessLog.timestamp >= start_date)
        
        logs = query.order_by(AccessLog.timestamp.desc()).limit(500).all()
        
        return jsonify({
            'logs': [{
                'id': log.id,
                'user': User.query.get(log.user_id).username,
                'document': Document.query.get(log.document_id).original_filename if Document.query.get(log.document_id) else 'Deleted',
                'action': log.action,
                'timestamp': log.timestamp.isoformat(),
                'ip_address': log.ip_address
            } for log in logs]
        }), 200
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Create share link
@app.route('/api/documents/<int:document_id>/share', methods=['POST'])
@token_required
def create_share_link(current_user, document_id):
    try:
        document = Document.query.get(document_id)
        
        if not document:
            return jsonify({'message': 'Document not found!'}), 404
        
        # Only document owner or admin can create share links
        if document.uploaded_by != current_user.id and current_user.role != 'admin':
            return jsonify({'message': 'Only document owner or admin can create share links!'}), 403
        
        data = request.get_json()
        expires_in_hours = data.get('expires_in_hours', 24)
        download_limit = data.get('download_limit')  # None = unlimited
        
        # Generate secure token
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)
        
        share_link = ShareLink(
            document_id=document_id,
            created_by=current_user.id,
            token=token,
            expires_at=expires_at,
            download_limit=download_limit
        )
        
        db.session.add(share_link)
        db.session.commit()
        
        log_access(current_user.id, document_id, 'share', request.remote_addr)
        
        return jsonify({
            'message': 'Share link created successfully!',
            'share_link': {
                'id': share_link.id,
                'token': token,
                'expires_at': expires_at.isoformat(),
                'download_limit': download_limit,
                'share_url': f'/api/documents/shared/{token}'
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Download via share link (no auth required)
@app.route('/api/documents/shared/<token>', methods=['GET'])
def download_shared(token):
    try:
        share_link = ShareLink.query.filter_by(token=token).first()
        
        if not share_link:
            return jsonify({'message': 'Invalid share link!'}), 404
        
        # Check if link is active
        if not share_link.is_active:
            return jsonify({'message': 'Share link is inactive!'}), 403
        
        # Check if link has expired
        if datetime.now(timezone.utc) > share_link.expires_at:
            return jsonify({'message': 'Share link has expired!'}), 403
        
        # Check download limit
        if share_link.download_limit and share_link.download_count >= share_link.download_limit:
            return jsonify({'message': 'Download limit exceeded!'}), 403
        
        document = Document.query.get(share_link.document_id)
        
        if not document:
            return jsonify({'message': 'Document not found!'}), 404
        
        # Increment download count
        share_link.download_count += 1
        db.session.commit()
        
        # Read and decrypt file
        with open(document.encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = encryption.decrypt_file(encrypted_data)
        
        # ✅ FIX: Use BytesIO to stream from memory (no temp files)
        file_stream = BytesIO(decrypted_data)
        
        return send_file(
            file_stream,
            as_attachment=True,
            download_name=document.original_filename,
            mimetype='application/octet-stream'
        )
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Get share links for a document
@app.route('/api/documents/<int:document_id>/shares', methods=['GET'])
@token_required
def get_share_links(current_user, document_id):
    try:
        document = Document.query.get(document_id)
        
        if not document:
            return jsonify({'message': 'Document not found!'}), 404
        
        # Only document owner or admin can view share links
        if document.uploaded_by != current_user.id and current_user.role != 'admin':
            return jsonify({'message': 'Only document owner or admin can view share links!'}), 403
        
        links = ShareLink.query.filter_by(document_id=document_id).all()
        
        return jsonify({
            'share_links': [{
                'id': link.id,
                'token': link.token,
                'created_by': User.query.get(link.created_by).username,
                'created_at': link.created_at.isoformat(),
                'expires_at': link.expires_at.isoformat(),
                'is_active': link.is_active,
                'download_limit': link.download_limit,
                'download_count': link.download_count
            } for link in links]
        }), 200
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Revoke share link
@app.route('/api/share/<int:share_id>', methods=['DELETE'])
@token_required
def revoke_share_link(current_user, share_id):
    try:
        share_link = ShareLink.query.get(share_id)
        
        if not share_link:
            return jsonify({'message': 'Share link not found!'}), 404
        
        document = Document.query.get(share_link.document_id)
        
        # Only document owner or admin can revoke
        if document.uploaded_by != current_user.id and current_user.role != 'admin':
            return jsonify({'message': 'Only document owner or admin can revoke share links!'}), 403
        
        share_link.is_active = False
        db.session.commit()
        
        return jsonify({'message': 'Share link revoked!'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Initialize database and create sample users
def init_db():
    with app.app_context():
        db.create_all()
        
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                password_hash=generate_password_hash('admin123'),
                role='admin'
            )
            db.session.add(admin)
        
        if not User.query.filter_by(username='editor').first():
            editor = User(
                username='editor',
                password_hash=generate_password_hash('editor123'),
                role='editor'
            )
            db.session.add(editor)
        
        if not User.query.filter_by(username='viewer').first():
            viewer = User(
                username='viewer',
                password_hash=generate_password_hash('viewer123'),
                role='viewer'
            )
            db.session.add(viewer)
        
        db.session.commit()
        print("[OK] Database initialized with sample users!")
        print("   Admin: admin/admin123")
        print("   Editor: editor/editor123")
        print("   Viewer: viewer/viewer123")

if __name__ == '__main__':
    init_db()
    
    # Check if SSL certificates exist for HTTPS
    ssl_context = None
    if os.path.exists('cert.pem') and os.path.exists('key.pem'):
        ssl_context = ('cert.pem', 'key.pem')
        print("[SSL] Running with HTTPS (self-signed certificate)")
    else:
        print("[INFO] Running with HTTP (development mode)")
        print("   Generate SSL cert: python generate_ssl.py")
    
    app.run(
        debug=app.config['DEBUG'],
        port=5000,
        ssl_context=ssl_context
    )