# 🔒 Secure Internal Document Sharing System

A full-stack web application for secure document management with role-based access control, end-to-end encryption, version control, and comprehensive audit logging.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![React](https://img.shields.io/badge/react-18.0+-blue.svg)
![Flask](https://img.shields.io/badge/flask-3.1+-green.svg)

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Security Features](#-security-features)
- [Tech Stack](#-tech-stack)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [User Roles & Permissions](#-user-roles--permissions)
- [API Documentation](#-api-documentation)
- [Security Best Practices](#-security-best-practices)
- [Deployment](#-deployment)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

### 🔐 Security
- **AES-256-GCM Encryption** - Military-grade encryption for documents at rest
- **JWT Authentication** - Secure token-based authentication
- **Role-Based Access Control (RBAC)** - Three-tier permission system
- **File Integrity Verification** - SHA-256 hashing prevents tampering
- **Audit Logging** - Complete activity trail with IP tracking
- **HTTPS Enforcement** - Secure communication in production
- **Security Headers** - XSS, clickjacking, and MIME-sniffing protection

### 📁 Document Management
- **Encrypted Storage** - All files encrypted before storage
- **Version Control** - Track document changes with rollback capability
- **Document Sharing** - Generate secure, expirable share links
- **Permission Management** - Granular document-level permissions
- **Multiple File Types** - Support for PDF, DOCX, XLSX, images, and more
- **File Size Limits** - Configurable upload size restrictions

### 👥 User Management
- **Auto-Assigned Roles** - New users start as viewers
- **Admin Role Management** - Admins can upgrade/downgrade user roles
- **Activity Dashboard** - Real-time monitoring of system activity
- **User Audit Trail** - Track all user actions and role changes

### 🎯 Additional Features
- **Idempotency Protection** - Prevent duplicate uploads
- **Download Limits** - Control share link access
- **Search & Filter** - Find documents and activities quickly
- **Responsive Design** - Works on desktop, tablet, and mobile
- **Real-time Updates** - Live activity monitoring

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Client (React)                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ Dashboard│  │  Login   │  │  Admin   │  │Documents │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
                          ↕ HTTPS/JWT
┌─────────────────────────────────────────────────────────────┐
│                    API Server (Flask)                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │   Auth   │  │Documents │  │  Sharing │  │  Admin   │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
                          ↕
┌─────────────────────────────────────────────────────────────┐
│                   Database (SQLite/PostgreSQL)               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │  Users   │  │Documents │  │Permissions│ │   Logs   │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
                          ↕
┌─────────────────────────────────────────────────────────────┐
│              Encrypted File Storage (Disk)                   │
│              All files encrypted with AES-256-GCM            │
└─────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Security Features

### Encryption
- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key Derivation**: PBKDF2-HMAC-SHA256 (100,000 iterations)
- **Unique Salt & Nonce**: Random 16-byte salt and 12-byte nonce per file
- **Authenticated Encryption**: Prevents tampering with built-in authentication tag

### File Integrity
- **Hash Algorithm**: SHA-256
- **Verification**: Automatic integrity check on download
- **Tamper Detection**: Alerts if file has been modified
- **Audit Trail**: Logs all integrity failures

### Access Control
- **JWT Tokens**: 24-hour expiration (configurable)
- **Role Hierarchy**: Admin → Editor → Viewer
- **Permission Inheritance**: Edit permission implies view permission
- **Owner Privileges**: Document owners have special rights

### Security Headers
```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: default-src 'self'
```

---

## 🛠️ Tech Stack

### Backend
- **Framework**: Flask 3.1.2
- **Database**: SQLite (development) / PostgreSQL (production)
- **ORM**: SQLAlchemy 3.1.1
- **Authentication**: JWT (PyJWT 2.10.1)
- **Encryption**: Cryptography 46.0.3
- **Password Hashing**: Werkzeug (PBKDF2)

### Frontend
- **Framework**: React 18.2+
- **Routing**: React Router
- **HTTP Client**: Axios
- **Styling**: CSS3 with custom components
- **State Management**: React Context API

### DevOps
- **CORS**: Flask-CORS 6.0.2
- **HTTPS**: SSL/TLS support
- **Environment**: Python 3.8+ required

---

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- Node.js 14+ and npm
- Git

### Backend Setup

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/secure-document-system.git
cd secure-document-system
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Set up environment variables**
```bash
# Create .env file
SECRET_KEY=your-super-secret-key-here
FLASK_DEBUG=False
DATABASE_URL=sqlite:///documents.db
UPLOAD_FOLDER=uploads
ENCRYPTED_FOLDER=encrypted_files
```

5. **Initialize database**
```bash
python app.py
# This will create the database and default users
```

### Frontend Setup

1. **Navigate to frontend directory**
```bash
cd frontend  # If separated, otherwise skip this
```

2. **Install dependencies**
```bash
npm install
```

3. **Configure API endpoint**
```bash
# Create .env file in frontend directory
REACT_APP_API_URL=http://localhost:5000/api
```

4. **Start development server**
```bash
npm start
```

---

## ⚙️ Configuration

### Backend Configuration (`config.py`)

```python
class Config:
    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///documents.db'
    
    # File Upload
    UPLOAD_FOLDER = 'uploads'
    ENCRYPTED_FOLDER = 'encrypted_files'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    
    # Allowed file types
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png', 'xlsx', 'csv'}
```

### Production Configuration

For production deployment:

```bash
# Set environment variables
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
export FLASK_DEBUG=False
export DATABASE_URL=postgresql://user:password@localhost/dbname
```

---

## 🚀 Usage

### Starting the Application

**Backend:**
```bash
# Development
python app.py

# Production (with Gunicorn)
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

**Frontend:**
```bash
# Development
npm start

# Production build
npm run build
```

### Default Accounts

The system creates three demo accounts on first run:

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Admin |
| editor | editor123 | Editor |
| viewer | viewer123 | Viewer |

⚠️ **Change these passwords immediately in production!**

### First-Time Setup

1. **Login as admin** (admin/admin123)
2. **Change admin password** via user settings
3. **Create additional users** or register new accounts
4. **Assign appropriate roles** using the admin panel
5. **Upload test documents** to verify functionality
6. **Review activity logs** in the admin dashboard

---

## 👥 User Roles & Permissions

### 👁️ Viewer Role
**Automatically assigned to all new users**

✅ **Can:**
- View all documents in the system
- Download any document
- View their own activity

❌ **Cannot:**
- Upload new documents
- Edit existing documents
- Delete documents
- Use version control
- Manage permissions
- Change user roles

### ✏️ Editor Role
**Must be assigned by admin**

✅ **Can (in addition to Viewer):**
- Upload new documents
- Edit their own documents
- Create new versions (version control)
- Rollback to previous versions (own docs)
- Share their own documents

❌ **Cannot:**
- Edit documents uploaded by others
- Delete documents (except own)
- Manage other users
- View system logs
- Change user roles

### 👑 Admin Role
**Full system access**

✅ **Can (in addition to Editor):**
- Edit ANY document
- Delete ANY document
- Manage all user roles
- View complete activity logs
- Grant/revoke permissions
- Create share links for any document
- Access admin panel
- View system statistics

---

## 📚 API Documentation

### Authentication

#### Register New User
```http
POST /api/register
Content-Type: application/json

{
  "username": "john_doe",
  "password": "securepassword123"
}

Response:
{
  "message": "Registration successful! Your account has been created with viewer permissions.",
  "username": "john_doe",
  "role": "viewer"
}
```

#### Login
```http
POST /api/login
Content-Type: application/json

{
  "username": "john_doe",
  "password": "securepassword123"
}

Response:
{
  "message": "Login successful!",
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": 1,
    "username": "john_doe",
    "role": "viewer"
  }
}
```

### Document Management

#### Upload Document
```http
POST /api/documents/upload
Authorization: Bearer <token>
Content-Type: multipart/form-data

file: <binary file data>

Response:
{
  "message": "File uploaded successfully!",
  "document": {
    "id": 1,
    "filename": "report.pdf",
    "size": 1024000
  }
}
```

#### Get All Documents
```http
GET /api/documents
Authorization: Bearer <token>

Response:
{
  "documents": [
    {
      "id": 1,
      "filename": "report.pdf",
      "uploaded_by": "john_doe",
      "upload_date": "2024-01-22T10:30:00",
      "file_size": 1024000,
      "can_edit": false
    }
  ]
}
```

#### Download Document
```http
GET /api/documents/<id>/download
Authorization: Bearer <token>

Response: Binary file data
```

### Admin Endpoints

#### List All Users (Admin Only)
```http
GET /api/admin/users
Authorization: Bearer <admin-token>

Response:
{
  "users": [
    {
      "id": 1,
      "username": "john_doe",
      "role": "viewer",
      "created_at": "2024-01-22T10:00:00"
    }
  ]
}
```

#### Change User Role (Admin Only)
```http
PUT /api/admin/users/<user_id>/role
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "role": "editor"
}

Response:
{
  "message": "User role updated from viewer to editor",
  "user": {
    "id": 1,
    "username": "john_doe",
    "old_role": "viewer",
    "new_role": "editor"
  }
}
```

### Version Control

#### Create New Version
```http
POST /api/documents/<id>/update
Authorization: Bearer <token>
Content-Type: multipart/form-data

file: <binary file data>
description: "Updated figures and conclusions"

Response:
{
  "message": "Document updated successfully!",
  "version": 2
}
```

#### Get Version History
```http
GET /api/documents/<id>/versions
Authorization: Bearer <token>

Response:
{
  "versions": [
    {
      "id": 2,
      "version_number": 2,
      "uploaded_by": "john_doe",
      "created_at": "2024-01-22T15:30:00",
      "file_size": 1048576,
      "change_description": "Updated figures"
    }
  ]
}
```

### Document Sharing

#### Create Share Link
```http
POST /api/documents/<id>/share
Authorization: Bearer <token>
Content-Type: application/json

{
  "expires_in_hours": 24,
  "download_limit": 10
}

Response:
{
  "message": "Share link created successfully!",
  "share_link": {
    "token": "abc123def456...",
    "expires_at": "2024-01-23T10:30:00",
    "download_limit": 10,
    "share_url": "/api/documents/shared/abc123def456..."
  }
}
```

---

## 🔒 Security Best Practices

### For Administrators

1. **Change default passwords immediately**
```bash
# Use strong, unique passwords for all admin accounts
```

2. **Enable HTTPS in production**
```bash
# Generate SSL certificate
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```

3. **Set strong SECRET_KEY**
```python
# Generate a secure secret key
python -c "import secrets; print(secrets.token_hex(32))"
```

4. **Use environment variables**
```bash
# Never commit secrets to version control
echo "SECRET_KEY=..." >> .env
echo ".env" >> .gitignore
```

5. **Regular backups**
```bash
# Backup database daily
sqlite3 documents.db ".backup 'backup-$(date +%Y%m%d).db'"
```

6. **Monitor activity logs**
```bash
# Review logs regularly for suspicious activity
# Check for failed login attempts, unusual downloads, etc.
```

### For Developers

1. **Keep dependencies updated**
```bash
pip install --upgrade -r requirements.txt
npm audit fix
```

2. **Validate all user input**
```python
# Always validate and sanitize user input
# Use parameterized queries (SQLAlchemy ORM does this)
```

3. **Follow principle of least privilege**
```python
# Users should have minimum necessary permissions
# Default role is 'viewer' for a reason
```

4. **Log security events**
```python
# Log all authentication attempts, permission changes, etc.
log_access(user_id, document_id, action, ip_address)
```

---

## 🌐 Deployment

### Production Deployment (Ubuntu/Debian)

1. **Install system dependencies**
```bash
sudo apt update
sudo apt install python3-pip python3-venv nginx postgresql
```

2. **Set up PostgreSQL**
```bash
sudo -u postgres createdb secure_docs
sudo -u postgres createuser -P docuser
# Grant privileges to docuser on secure_docs database
```

3. **Configure application**
```bash
export DATABASE_URL=postgresql://docuser:password@localhost/secure_docs
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export FLASK_DEBUG=False
```

4. **Install application**
```bash
cd /var/www/secure-docs
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install gunicorn
```

5. **Create systemd service**
```ini
# /etc/systemd/system/secure-docs.service
[Unit]
Description=Secure Document Sharing System
After=network.target

[Service]
User=www-data
WorkingDirectory=/var/www/secure-docs
Environment="PATH=/var/www/secure-docs/venv/bin"
Environment="SECRET_KEY=your-secret-key"
Environment="DATABASE_URL=postgresql://user:pass@localhost/db"
ExecStart=/var/www/secure-docs/venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 app:app

[Install]
WantedBy=multi-user.target
```

6. **Configure Nginx**
```nginx
# /etc/nginx/sites-available/secure-docs
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

7. **Start services**
```bash
sudo systemctl enable secure-docs
sudo systemctl start secure-docs
sudo systemctl restart nginx
```

### Docker Deployment

```dockerfile
# Dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  web:
    build: .
    ports:
      - "5000:5000"
    environment:
      - SECRET_KEY=${SECRET_KEY}
      - DATABASE_URL=postgresql://postgres:password@db:5432/secure_docs
    depends_on:
      - db
    volumes:
      - ./uploads:/app/uploads
      - ./encrypted_files:/app/encrypted_files

  db:
    image: postgres:13
    environment:
      - POSTGRES_DB=secure_docs
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

```bash
# Deploy with Docker
docker-compose up -d
```

---

## 🐛 Troubleshooting

### Common Issues

#### "Token is missing!" error
**Cause**: Not logged in or token expired
**Solution**:
```bash
# Clear localStorage and login again
localStorage.clear()
```

#### "File too large!" error
**Cause**: File exceeds 16MB limit
**Solution**:
```python
# Increase limit in config.py
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB
```

#### "Database locked" error (SQLite)
**Cause**: Concurrent write operations
**Solution**:
```python
# Switch to PostgreSQL for production
DATABASE_URL = 'postgresql://user:pass@localhost/dbname'
```

#### "CORS error" in browser
**Cause**: Frontend and backend on different origins
**Solution**:
```python
# In app.py
CORS(app, resources={r"/api/*": {"origins": ["http://localhost:3000"]}})
```

#### Files not encrypting
**Cause**: Missing encryption key
**Solution**:
```bash
# Ensure SECRET_KEY is set
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
```

### Debug Mode

Enable debug logging:
```python
# In app.py
import logging
logging.basicConfig(level=logging.DEBUG)
app.config['DEBUG'] = True
```

View logs:
```bash
# Flask logs
tail -f /var/log/secure-docs/app.log

# Nginx logs
tail -f /var/log/nginx/error.log
```

---

## 📈 Performance Optimization

### Backend Optimization

1. **Database Indexing**
```python
# Add indexes to frequently queried columns
class Document(db.Model):
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    idempotency_key = db.Column(db.String(64), unique=True, index=True)
```

2. **Caching**
```python
from flask_caching import Cache
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

@cache.cached(timeout=300)
def get_documents():
    # Cached for 5 minutes
    pass
```

3. **Connection Pooling**
```python
# Use connection pooling with PostgreSQL
SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_size': 10,
    'pool_recycle': 3600,
}
```

### Frontend Optimization

1. **Code Splitting**
```javascript
const Dashboard = React.lazy(() => import('./Dashboard'));
```

2. **Memoization**
```javascript
const documents = useMemo(() => 
  filterDocuments(allDocuments), 
  [allDocuments]
);
```

3. **Production Build**
```bash
npm run build
# Minifies and optimizes for production
```

---

## 🧪 Testing

### Backend Tests

```python
# test_app.py
import unittest
from app import app, db

class TestAuth(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        
    def test_register(self):
        response = self.client.post('/api/register', json={
            'username': 'testuser',
            'password': 'testpass123'
        })
        self.assertEqual(response.status_code, 201)
        data = response.get_json()
        self.assertEqual(data['role'], 'viewer')

if __name__ == '__main__':
    unittest.main()
```

Run tests:
```bash
python -m pytest test_app.py
```

### Frontend Tests

```javascript
// Login.test.js
import { render, screen } from '@testing-library/react';
import Login from './Login';

test('renders login form', () => {
  render(<Login />);
  const usernameInput = screen.getByPlaceholderText(/username/i);
  expect(usernameInput).toBeInTheDocument();
});
```

Run tests:
```bash
npm test
```

---

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

1. **Fork the repository**
```bash
git clone https://github.com/your-fork/secure-document-system.git
```

2. **Create a feature branch**
```bash
git checkout -b feature/amazing-feature
```

3. **Make your changes**
- Follow PEP 8 for Python code
- Use ESLint for JavaScript code
- Write tests for new features
- Update documentation

4. **Commit your changes**
```bash
git commit -m "Add amazing feature"
```

5. **Push to your fork**
```bash
git push origin feature/amazing-feature
```

6. **Open a Pull Request**
- Describe your changes
- Reference any related issues
- Wait for review

### Code Style

**Python:**
```python
# Use Black formatter
black app.py

# Use Flake8 for linting
flake8 app.py
```

**JavaScript:**
```bash
# Use Prettier
npm run format

# Use ESLint
npm run lint
```

---

## 📄 License

This project is licensed under the MIT License.

```
MIT License

Copyright (c) 2024 Secure Document Sharing System

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🙏 Acknowledgments

- **Flask** - Lightweight WSGI web application framework
- **React** - JavaScript library for building user interfaces
- **Cryptography** - Cryptographic recipes and primitives
- **SQLAlchemy** - Python SQL toolkit and ORM
- **Material Design** - Design inspiration

---

## 📞 Support

- **Documentation**: See `/docs` folder for detailed guides
- **Issues**: Report bugs on [GitHub Issues](https://github.com/yourusername/secure-document-system/issues)
- **Email**: support@yourdomain.com
- **Discord**: Join our [Discord server](https://discord.gg/yourinvite)

---

## 🗺️ Roadmap

### Version 2.0 (Planned)
- [ ] Two-factor authentication (2FA)
- [ ] Email notifications for role changes
- [ ] Advanced search with filters
- [ ] Document collaboration features
- [ ] Mobile app (React Native)
- [ ] API rate limiting
- [ ] Webhook support
- [ ] SSO integration (LDAP, OAuth)

### Version 2.1 (Future)
- [ ] Real-time document editing
- [ ] Document comments and annotations
- [ ] Advanced analytics dashboard
- [ ] Custom branding options
- [ ] Multi-language support
- [ ] Dark mode theme

---

## ⭐ Star History

If you find this project useful, please consider giving it a star on GitHub!

---

**Built with ❤️ for secure document management**

Last updated: January 22, 2024