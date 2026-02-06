from flask import Flask, request, jsonify, send_file, redirect
from flask_cors import CORS
from flask_login import LoginManager
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from config import Config
from models import db, User, Document, AccessLog, DocumentPermission, DocumentVersion, ShareLink, get_ist_now
from encryption import DocumentEncryption
import jwt
from datetime import datetime, timedelta, timezone
from functools import wraps
import os
import uuid
import secrets
from io import BytesIO
import hashlib

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
    
    # Check explicit file-level permissions first (before role-based restrictions)
    # This allows granting specific users access even if their role doesn't normally allow it
    perm = DocumentPermission.query.filter_by(
        document_id=document.id,
        user_id=user.id
    ).first()
    
    # Debug logging
    print(f"[PERMISSION CHECK] User ID: {user.id}, Document ID: {document.id}, Permission Type: {permission}")
    print(f"[PERMISSION CHECK] Found explicit permission: {perm}")
    if perm:
        print(f"[PERMISSION CHECK] Explicit permission level: {perm.permission}")
    
    if perm:
        # 'edit' permission implies 'view' permission
        if permission == 'view':
            result = perm.permission in ['view', 'edit']
            print(f"[PERMISSION CHECK] View check result: {result}")
            return result
        elif permission == 'edit':
            result = perm.permission == 'edit'
            print(f"[PERMISSION CHECK] Edit check result: {result}")
            return result
    
    # For view permission: All authenticated users can view (viewers, editors, admins)
    if permission == 'view':
        return True
    
    # For edit permission: Only editors and admins (and owner) can edit
    if permission == 'edit':
        if user.role in ['editor', 'admin']:
            return True
        # Check if owner (already checked above but keeping for clarity)
        if document.uploaded_by == user.id:
            return True
    
    print(f"[PERMISSION CHECK] Final result: False (no matching permission)")
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

# ✅ UPDATED: Registration always creates viewer role
@app.route('/api/register', methods=['POST'])
def register():
    """
    Register new user with DEFAULT 'viewer' role.
    Users cannot select their role - it's always 'viewer'.
    Only admins can upgrade roles via /api/admin/users/<id>/role endpoint.
    """
    try:
        data = request.get_json()
        
        username = data.get('username')
        password = data.get('password')
        
        # Validation
        if not username or not password:
            return jsonify({'message': 'Username and password are required!'}), 400
        
        if len(username) < 3:
            return jsonify({'message': 'Username must be at least 3 characters!'}), 400
        
        if len(password) < 8:
            return jsonify({'message': 'Password must be at least 8 characters!'}), 400
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            return jsonify({'message': 'Username already exists!'}), 400
        
        # Create user with VIEWER role (role is NOT taken from request)
        password_hash = generate_password_hash(password)
        new_user = User(
            username=username, 
            password_hash=password_hash, 
            role='viewer'  # ✅ ALWAYS set to 'viewer'
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        # Log registration
        log_access(new_user.id, None, 'register', request.remote_addr)
        
        return jsonify({
            'message': 'Registration successful! Your account has been created with viewer permissions. Contact an admin to request role upgrades.',
            'username': username,
            'role': 'viewer'
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
            return jsonify({'message': 'Invalid credentials!'}), 401
        
        # Generate JWT token
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.now(timezone.utc) + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
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
        'user': {
            'id': current_user.id,
            'username': current_user.username,
            'role': current_user.role
        }
    }), 200

# ✅ NEW: Admin endpoint to list all users
@app.route('/api/admin/users', methods=['GET'])
@token_required
@role_required('admin')
def get_all_users(current_user):
    """
    Get list of all users (admin only) for role management.
    """
    try:
        users = User.query.all()
        
        users_list = [{
            'id': user.id,
            'username': user.username,
            'role': user.role,
            'created_at': user.created_at.isoformat() if hasattr(user, 'created_at') else None
        } for user in users]
        
        return jsonify({'users': users_list}), 200
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

# ✅ NEW: Admin endpoint to change user roles
@app.route('/api/admin/users/<int:user_id>/role', methods=['PUT'])
@token_required
@role_required('admin')
def update_user_role(current_user, user_id):
    """
    Admin-only endpoint to change user roles.
    Allows upgrading users from viewer -> editor or viewer/editor -> admin.
    """
    try:
        data = request.get_json()
        new_role = data.get('role')
        
        # Validate role
        if new_role not in ['admin', 'editor', 'viewer']:
            return jsonify({'message': 'Invalid role! Must be admin, editor, or viewer.'}), 400
        
        # Get target user
        user = User.query.get(user_id)
        if not user:
            return jsonify({'message': 'User not found!'}), 404
        
        # Prevent admin from demoting themselves
        if user.id == current_user.id and new_role != 'admin':
            return jsonify({'message': 'You cannot change your own admin role!'}), 400
        
        old_role = user.role
        user.role = new_role
        db.session.commit()
        
        # Log the role change
        log_access(
            current_user.id, 
            None, 
            f'role_change_{old_role}_to_{new_role}_user_{user_id}', 
            request.remote_addr
        )
        
        return jsonify({
            'message': f'User role updated from {old_role} to {new_role}',
            'user': {
                'id': user.id,
                'username': user.username,
                'old_role': old_role,
                'new_role': new_role
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/users', methods=['GET'])
@token_required
def get_users(current_user):
    try:
        users = User.query.all()
        return jsonify({
            'users': [{
                'id': user.id,
                'username': user.username,
                'role': user.role
            } for user in users]
        }), 200
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Upload document (with encryption and integrity check)
@app.route('/api/documents/upload', methods=['POST'])
@token_required
def upload_document(current_user):
    try:
        # Check role - only editors and admins can upload
        if current_user.role not in ['editor', 'admin']:
            return jsonify({'message': 'Only editors and admins can upload documents!'}), 403
        
        if 'file' not in request.files:
            return jsonify({'message': 'No file uploaded!'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'message': 'No file selected!'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'message': 'File type not allowed!'}), 400
        
        # Generate idempotency key from request header or create one
        idempotency_key = request.headers.get('X-Idempotency-Key', str(uuid.uuid4()))
        
        # Check if this file was already uploaded (idempotency check)
        existing_doc = Document.query.filter_by(idempotency_key=idempotency_key).first()
        if existing_doc:
            return jsonify({
                'message': 'Document already uploaded (duplicate request detected)',
                'document': {
                    'id': existing_doc.id,
                    'filename': existing_doc.original_filename
                }
            }), 200
        
        # Read file data
        file_data = file.read()
        
        # Calculate file hash for integrity
        file_hash = calculate_file_hash(file_data)
        
        # Encrypt file
        encrypted_data = encryption.encrypt_file(file_data)
        
        # Generate unique filename
        original_filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{original_filename}"
        encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], unique_filename)
        
        # Save encrypted file
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Store document metadata
        document = Document(
            filename=unique_filename,
            original_filename=original_filename,
            encrypted_path=encrypted_path,
            uploaded_by=current_user.id,
            file_type=file.content_type,
            file_size=len(file_data),
            file_hash=file_hash,
            idempotency_key=idempotency_key
        )
        
        db.session.add(document)
        db.session.commit()
        
        # Create initial version
        version = DocumentVersion(
            document_id=document.id,
            version_number=1,
            encrypted_path=encrypted_path,
            uploaded_by=current_user.id,
            file_size=len(file_data),
            file_hash=file_hash,
            change_description='Initial upload'
        )
        
        db.session.add(version)
        db.session.commit()
        
        # Log upload
        log_access(current_user.id, document.id, 'upload', request.remote_addr)
        
        return jsonify({
            'message': 'File uploaded successfully!',
            'document': {
                'id': document.id,
                'filename': document.original_filename,
                'size': document.file_size
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Get all documents
@app.route('/api/documents', methods=['GET'])
@token_required
def get_documents(current_user):
    try:
        # All users can see all documents (viewers can view, editors can edit their own)
        documents = Document.query.all()
        
        docs_list = []
        for doc in documents:
            uploader = User.query.get(doc.uploaded_by)
            docs_list.append({
                'id': doc.id,
                'filename': doc.original_filename,
                'uploaded_by': uploader.username if uploader else 'Unknown',
                'uploaded_by_id': doc.uploaded_by,
                'upload_date': doc.upload_date.isoformat(),
                'file_type': doc.file_type,
                'file_size': doc.file_size,
                'can_edit': check_document_permission(current_user, doc, 'edit')
            })
        
        return jsonify({'documents': docs_list}), 200
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Download document (with integrity verification)
@app.route('/api/documents/<int:document_id>/download', methods=['GET'])
@token_required
def download_document(current_user, document_id):
    try:
        document = Document.query.get(document_id)
        
        if not document:
            return jsonify({'message': 'Document not found!'}), 404
        
        # Check if user has permission to view
        if not check_document_permission(current_user, document, 'view'):
            return jsonify({'message': 'Access denied!'}), 403
        
        # Read and decrypt file
        with open(document.encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = encryption.decrypt_file(encrypted_data)
        
        # Verify file integrity
        if not verify_file_integrity(decrypted_data, document.file_hash):
            log_access(current_user.id, document_id, 'integrity_failure', request.remote_addr)
            return jsonify({'message': 'File integrity check failed!'}), 500
        
        # Log download
        log_access(current_user.id, document_id, 'download', request.remote_addr)
        
        # Use BytesIO to stream from memory (no temp files)
        file_stream = BytesIO(decrypted_data)
        
        # Get MIME type based on file extension
        mime_types = {
            'pdf': 'application/pdf',
            'txt': 'text/plain',
            'doc': 'application/msword',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'csv': 'text/csv'
        }
        
        file_ext = document.original_filename.rsplit('.', 1)[-1].lower() if '.' in document.original_filename else ''
        mime_type = mime_types.get(file_ext, 'application/octet-stream')
        
        # Check if preview mode (don't force download)
        is_preview = request.args.get('preview', 'false').lower() == 'true'
        
        return send_file(
            file_stream,
            as_attachment=not is_preview,
            download_name=document.original_filename,
            mimetype=mime_type
        )
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Delete document (admin or owner only)
@app.route('/api/documents/<int:document_id>', methods=['DELETE'])
@token_required
def delete_document(current_user, document_id):
    try:
        document = Document.query.get(document_id)
        
        if not document:
            return jsonify({'message': 'Document not found!'}), 404
        
        # Only admin or document owner can delete
        if current_user.role != 'admin' and document.uploaded_by != current_user.id:
            return jsonify({'message': 'Only admin or document owner can delete!'}), 403
        
        # Delete encrypted file
        if os.path.exists(document.encrypted_path):
            os.remove(document.encrypted_path)
        
        # Delete all versions
        versions = DocumentVersion.query.filter_by(document_id=document_id).all()
        for version in versions:
            if os.path.exists(version.encrypted_path) and version.encrypted_path != document.encrypted_path:
                os.remove(version.encrypted_path)
            db.session.delete(version)
        
        # Delete permissions
        permissions = DocumentPermission.query.filter_by(document_id=document_id).all()
        for perm in permissions:
            db.session.delete(perm)
        
        # Log deletion before deleting the document
        log_access(current_user.id, document_id, 'delete', request.remote_addr)
        
        # Delete document
        db.session.delete(document)
        db.session.commit()
        
        return jsonify({'message': 'Document deleted successfully!'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Update document (create new version) - EDITORS AND ADMINS ONLY
@app.route('/api/documents/<int:document_id>/update', methods=['POST'])
@token_required
def update_document(current_user, document_id):
    try:
        document = Document.query.get(document_id)
        
        if not document:
            return jsonify({'message': 'Document not found!'}), 404
        
        # ✅ Check if user can edit - editors can only edit their own docs, admins can edit all
        if not check_document_permission(current_user, document, 'edit'):
            return jsonify({'message': 'You do not have permission to edit this document!'}), 403
        
        if 'file' not in request.files:
            return jsonify({'message': 'No file uploaded!'}), 400
        
        file = request.files['file']
        description = request.form.get('description', 'Updated version')
        
        if file.filename == '':
            return jsonify({'message': 'No file selected!'}), 400
        
        # Read and encrypt new file
        file_data = file.read()
        file_hash = calculate_file_hash(file_data)
        encrypted_data = encryption.encrypt_file(file_data)
        
        # Get current highest version number
        last_version = DocumentVersion.query.filter_by(document_id=document_id).order_by(DocumentVersion.version_number.desc()).first()
        new_version_number = (last_version.version_number + 1) if last_version else 1
        
        # Generate unique filename for new version
        unique_filename = f"{uuid.uuid4()}_{document.original_filename}"
        encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], unique_filename)
        
        # Save encrypted file
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Create new version
        version = DocumentVersion(
            document_id=document_id,
            version_number=new_version_number,
            encrypted_path=encrypted_path,
            uploaded_by=current_user.id,
            file_size=len(file_data),
            file_hash=file_hash,
            change_description=description
        )
        
        db.session.add(version)
        
        # Update main document to point to latest version
        document.encrypted_path = encrypted_path
        document.file_size = len(file_data)
        document.file_hash = file_hash
        
        db.session.commit()
        
        # Log update
        log_access(current_user.id, document_id, 'update', request.remote_addr)
        
        return jsonify({
            'message': 'Document updated successfully!',
            'version': new_version_number
        }), 200
        
    except Exception as e:
        db.session.rollback()
        if 'encrypted_path' in locals() and os.path.exists(encrypted_path):
            os.remove(encrypted_path)
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Get document versions
@app.route('/api/documents/<int:document_id>/versions', methods=['GET'])
@token_required
def get_versions(current_user, document_id):
    try:
        document = Document.query.get(document_id)
        
        if not document:
            return jsonify({'message': 'Document not found!'}), 404
        
        if not check_document_permission(current_user, document, 'view'):
            return jsonify({'message': 'Access denied!'}), 403
        
        versions = DocumentVersion.query.filter_by(document_id=document_id).order_by(DocumentVersion.version_number.desc()).all()
        
        versions_list = []
        for ver in versions:
            uploader = User.query.get(ver.uploaded_by)
            versions_list.append({
                'id': ver.id,
                'version_number': ver.version_number,
                'uploaded_by': uploader.username if uploader else 'Unknown',
                'created_at': ver.created_at.isoformat(),
                'file_size': ver.file_size,
                'change_description': ver.change_description
            })
        
        return jsonify({'versions': versions_list}), 200
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Rollback to previous version - EDITORS AND ADMINS ONLY
@app.route('/api/documents/<int:document_id>/rollback/<int:version_id>', methods=['POST'])
@token_required
def rollback_version(current_user, document_id, version_id):
    try:
        document = Document.query.get(document_id)
        
        if not document:
            return jsonify({'message': 'Document not found!'}), 404
        
        # ✅ Check if user can edit
        if not check_document_permission(current_user, document, 'edit'):
            return jsonify({'message': 'You do not have permission to rollback this document!'}), 403
        
        version = DocumentVersion.query.get(version_id)
        
        if not version or version.document_id != document_id:
            return jsonify({'message': 'Version not found!'}), 404
        
        # Update main document to point to this version
        document.encrypted_path = version.encrypted_path
        document.file_size = version.file_size
        document.file_hash = version.file_hash
        
        db.session.commit()
        
        # Log rollback
        log_access(current_user.id, document_id, f'rollback_to_v{version.version_number}', request.remote_addr)
        
        return jsonify({
            'message': f'Rolled back to version {version.version_number}',
            'version': version.version_number
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Grant permission to user
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
        permission = data.get('permission', 'view')
        
        if permission not in ['view', 'edit']:
            return jsonify({'message': 'Invalid permission type!'}), 400
        
        # Check if permission already exists
        existing_perm = DocumentPermission.query.filter_by(
            document_id=document_id,
            user_id=user_id
        ).first()
        
        if existing_perm:
            existing_perm.permission = permission
            existing_perm.granted_by = current_user.id
            existing_perm.granted_at = get_ist_now()
        else:
            perm = DocumentPermission(
                document_id=document_id,
                user_id=user_id,
                permission=permission,
                granted_by=current_user.id
            )
            db.session.add(perm)
        
        db.session.commit()
        
        return jsonify({'message': 'Permission granted successfully!'}), 201
        
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
        
        permissions = DocumentPermission.query.filter_by(document_id=document_id).all()
        
        perms_list = []
        for perm in permissions:
            user = User.query.get(perm.user_id)
            granter = User.query.get(perm.granted_by)
            perms_list.append({
                'id': perm.id,
                'user_id': perm.user_id,
                'username': user.username if user else 'Unknown',
                'permission': perm.permission,
                'granted_by': granter.username if granter else 'Unknown',
                'granted_at': perm.granted_at.isoformat()
            })
        
        return jsonify({'permissions': perms_list}), 200
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Revoke permission
@app.route('/api/documents/<int:document_id>/permissions/<int:permission_id>', methods=['DELETE'])
@token_required
def revoke_permission(current_user, document_id, permission_id):
    try:
        document = Document.query.get(document_id)
        
        if not document:
            return jsonify({'message': 'Document not found!'}), 404
        
        # Only document owner or admin can revoke permissions
        if document.uploaded_by != current_user.id and current_user.role != 'admin':
            return jsonify({'message': 'Only document owner or admin can revoke permissions!'}), 403
        
        permission = DocumentPermission.query.get(permission_id)
        
        if not permission or permission.document_id != document_id:
            return jsonify({'message': 'Permission not found!'}), 404
        
        db.session.delete(permission)
        db.session.commit()
        
        return jsonify({'message': 'Permission revoked!'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Revoke permission by user_id (alternative endpoint for convenience)
@app.route('/api/documents/<int:document_id>/permissions/user/<int:user_id>', methods=['DELETE'])
@token_required
def revoke_permission_by_user(current_user, document_id, user_id):
    try:
        document = Document.query.get(document_id)
        
        if not document:
            return jsonify({'message': 'Document not found!'}), 404
        
        # Only document owner or admin can revoke permissions
        if document.uploaded_by != current_user.id and current_user.role != 'admin':
            return jsonify({'message': 'Only document owner or admin can revoke permissions!'}), 403
        
        permission = DocumentPermission.query.filter_by(
            document_id=document_id,
            user_id=user_id
        ).first()
        
        if not permission:
            return jsonify({'message': 'Permission not found!'}), 404
        
        db.session.delete(permission)
        db.session.commit()
        
        return jsonify({'message': 'Permission revoked!'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Get activity logs (admin only)
@app.route('/api/logs', methods=['GET'])
@token_required
@role_required('admin')
def get_logs(current_user):
    try:
        days = request.args.get('days', 7, type=int)
        action_filter = request.args.get('action', None)
        
        # Calculate start date
        start_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        # Query logs
        query = AccessLog.query.filter(AccessLog.timestamp >= start_date)
        
        if action_filter:
            query = query.filter(AccessLog.action == action_filter)
        
        logs = query.order_by(AccessLog.timestamp.desc()).all()
        
        return jsonify({
            'logs': [{
                'id': log.id,
                'user': User.query.get(log.user_id).username,
                'document': Document.query.get(log.document_id).original_filename if log.document_id and Document.query.get(log.document_id) else 'N/A',
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
        
        # Use BytesIO to stream from memory (no temp files)
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
