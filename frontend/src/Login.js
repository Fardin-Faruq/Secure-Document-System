import React, { useState } from 'react';
import { useAuth } from './AuthContext';
import './Login.css';

function Login() {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [messageType, setMessageType] = useState('');
  
  const { login, register } = useAuth();

  // Validate input before submission
  const validateInput = () => {
    if (username.length < 3) {
      setMessage('Username must be at least 3 characters');
      setMessageType('error');
      return false;
    }
    
    if (password.length < 8) {
      setMessage('Password must be at least 8 characters');
      setMessageType('error');
      return false;
    }
    
    return true;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage('');

    if (!validateInput()) {
      return;
    }

    if (isLogin) {
      const result = await login(username, password);
      if (!result.success) {
        setMessage(result.message);
        setMessageType('error');
      }
    } else {
      // Registration - role is NOT sent, backend will set it to 'viewer'
      const result = await register(username, password);
      setMessage(result.message);
      setMessageType(result.success ? 'success' : 'error');
      
      if (result.success) {
        setTimeout(() => {
          setIsLogin(true);
          setMessage('');
          setPassword('');
        }, 3000);
      }
    }
  };

  return (
    <div className="login-container">
      <div className="login-box">
        <h1>🔒 Secure Document System</h1>
        <h2>{isLogin ? 'Login' : 'Register'}</h2>
        
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Username:</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              placeholder="Enter username (min 3 characters)"
              minLength="3"
            />
          </div>

          <div className="form-group">
            <label>Password:</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              placeholder="Enter password (min 8 characters)"
              minLength="8"
            />
          </div>

          {/* ✅ REMOVED: Role selection dropdown - users are auto-assigned 'viewer' role */}
          {!isLogin && (
            <div className="info-message">
              <p>ℹ️ New accounts are created with <strong>Viewer</strong> permissions by default.</p>
              <p>Contact an admin to request Editor or Admin role upgrades.</p>
            </div>
          )}

          {message && (
            <div className={`message ${messageType}`}>
              {message}
            </div>
          )}

          <button type="submit" className="submit-btn">
            {isLogin ? 'Login' : 'Register'}
          </button>
        </form>

        <p className="toggle-text">
          {isLogin ? "Don't have an account? " : "Already have an account? "}
          <span onClick={() => {
            setIsLogin(!isLogin);
            setMessage('');
            setMessageType('');
          }}>
            {isLogin ? 'Register' : 'Login'}
          </span>
        </p>

        <div className="demo-accounts">
          <p><strong>Demo Accounts:</strong></p>
          <p>👤 Admin: admin / admin123</p>
          <p>✏️ Editor: editor / editor123</p>
          <p>👁️ Viewer: viewer / viewer123</p>
        </div>

        <div className="role-info">
          <p><strong>Role Permissions:</strong></p>
          <ul>
            <li><strong>Viewer:</strong> Can view and download all documents</li>
            <li><strong>Editor:</strong> Can view, download, upload new documents, and edit their own documents (version control)</li>
            <li><strong>Admin:</strong> Full access - can manage all documents, users, and system settings</li>
          </ul>
        </div>
      </div>
    </div>
  );
}

export default Login;
