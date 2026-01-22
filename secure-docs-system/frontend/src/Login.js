import React, { useState } from 'react';
import { useAuth } from './AuthContext';
import './Login.css';

function Login() {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('viewer');
  const [message, setMessage] = useState('');
  const [messageType, setMessageType] = useState('');
  
  const { login, register } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage('');

    if (isLogin) {
      const result = await login(username, password);
      if (!result.success) {
        setMessage(result.message);
        setMessageType('error');
      }
    } else {
      const result = await register(username, password, role);
      setMessage(result.message);
      setMessageType(result.success ? 'success' : 'error');
      
      if (result.success) {
        setTimeout(() => {
          setIsLogin(true);
          setMessage('');
          setPassword('');
        }, 2000);
      }
    }
  };

  return (
    <div className="login-container">
      <div className="login-box">
        <h1>🔐 Secure Document System</h1>
        <h2>{isLogin ? 'Login' : 'Register'}</h2>
        
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Username:</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              placeholder="Enter username"
            />
          </div>

          <div className="form-group">
            <label>Password:</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              placeholder="Enter password"
            />
          </div>

          {!isLogin && (
            <div className="form-group">
              <label>Role:</label>
              <select value={role} onChange={(e) => setRole(e.target.value)}>
                <option value="viewer">Viewer (Read Only)</option>
                <option value="editor">Editor (Read & Upload)</option>
                <option value="admin">Admin (Full Access)</option>
              </select>
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
          }}>
            {isLogin ? 'Register' : 'Login'}
          </span>
        </p>

        <div className="demo-accounts">
          <p><strong>Demo Accounts:</strong></p>
          <p>Admin: admin / admin123</p>
          <p>Editor: editor / editor123</p>
          <p>Viewer: viewer / viewer123</p>
        </div>
      </div>
    </div>
  );
}

export default Login;