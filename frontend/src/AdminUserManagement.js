import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './AdminUserManagement.css';

function AdminUserManagement({ token, currentUser }) {
  const [users, setUsers] = useState([]);
  const [documents, setDocuments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState('');
  const [messageType, setMessageType] = useState('');
  const [activeTab, setActiveTab] = useState('users'); // 'users' or 'filePermissions'
  
  // File permissions state
  const [selectedUser, setSelectedUser] = useState('');
  const [selectedDocument, setSelectedDocument] = useState('');
  const [selectedPermission, setSelectedPermission] = useState('view');
  const [grantingPermission, setGrantingPermission] = useState(false);

  const API_URL = 'http://localhost:5000/api';

  const fetchUsers = async () => {
    try {
      setLoading(true);
      const response = await axios.get(`${API_URL}/admin/users`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setUsers(response.data.users);
    } catch (error) {
      setMessage('Failed to load users');
      setMessageType('error');
    } finally {
      setLoading(false);
    }
  };

  const fetchDocuments = async () => {
    try {
      const response = await axios.get(`${API_URL}/documents`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setDocuments(response.data.documents);
    } catch (error) {
      console.error('Failed to load documents:', error);
    }
  };

  useEffect(() => {
    if (currentUser.role === 'admin') {
      fetchUsers();
      fetchDocuments();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentUser]);

  const handleRoleChange = async (userId, newRole, username) => {
    if (!window.confirm(`Change ${username}'s role to ${newRole}?`)) {
      return;
    }

    try {
      const response = await axios.put(
        `${API_URL}/admin/users/${userId}/role`,
        { role: newRole },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
      setMessage(response.data.message);
      setMessageType('success');
      fetchUsers(); // Refresh user list
      
      setTimeout(() => setMessage(''), 3000);
    } catch (error) {
      setMessage(error.response?.data?.message || 'Failed to update role');
      setMessageType('error');
    }
  };

  const handleGrantFilePermission = async (e) => {
    e.preventDefault();
    
    if (!selectedUser || !selectedDocument) {
      setMessage('Please select both a user and a document');
      setMessageType('error');
      return;
    }

    setGrantingPermission(true);
    try {
      await axios.post(
        `${API_URL}/documents/${selectedDocument}/permissions`,
        { 
          user_id: parseInt(selectedUser), 
          permission: selectedPermission 
        },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
      setMessage(`Permission granted: ${getUsernameById(selectedUser)} now has ${selectedPermission} access to this file`);
      setMessageType('success');
      setSelectedUser('');
      setSelectedDocument('');
      setSelectedPermission('view');
      
      setTimeout(() => setMessage(''), 4000);
    } catch (error) {
      setMessage(error.response?.data?.message || 'Failed to grant permission');
      setMessageType('error');
    } finally {
      setGrantingPermission(false);
    }
  };

  const getUsernameById = (userId) => {
    const user = users.find(u => u.id === parseInt(userId));
    return user ? user.username : 'User';
  };

  const getRoleBadgeClass = (role) => {
    switch (role) {
      case 'admin': return 'role-badge-admin';
      case 'editor': return 'role-badge-editor';
      case 'viewer': return 'role-badge-viewer';
      default: return 'role-badge-viewer';
    }
  };

  const getRoleIcon = (role) => {
    switch (role) {
      case 'admin': return '👑';
      case 'editor': return '✏️';
      case 'viewer': return '👁️';
      default: return '👤';
    }
  };

  if (currentUser.role !== 'admin') {
    return (
      <div className="admin-access-denied">
        <p>⚠️ Admin access required to manage users.</p>
      </div>
    );
  }

  return (
    <div className="admin-user-management">
      <div className="admin-header">
        <h2>👥 Admin Panel</h2>
        <p className="admin-subtitle">Manage user roles and file-level permissions</p>
      </div>

      {message && (
        <div className={`admin-message ${messageType}`}>
          {message}
        </div>
      )}

      {/* Tabs */}
      <div className="admin-tabs">
        <button 
          className={`admin-tab-btn ${activeTab === 'users' ? 'active' : ''}`}
          onClick={() => setActiveTab('users')}
        >
          User Roles
        </button>
        <button 
          className={`admin-tab-btn ${activeTab === 'filePermissions' ? 'active' : ''}`}
          onClick={() => setActiveTab('filePermissions')}
        >
          File Permissions
        </button>
      </div>

      {/* Users Tab */}
      {activeTab === 'users' && (
        <>
          {loading ? (
            <div className="loading">Loading users...</div>
          ) : (
            <div className="users-table-container">
              <table className="users-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Username</th>
                    <th>Current Role</th>
                    <th>Created At</th>
                    <th>Change Role</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map(user => (
                    <tr key={user.id} className={user.id === currentUser.id ? 'current-user-row' : ''}>
                      <td>{user.id}</td>
                      <td>
                        <strong>{user.username}</strong>
                        {user.id === currentUser.id && <span className="you-badge"> (You)</span>}
                      </td>
                      <td>
                        <span className={`role-badge ${getRoleBadgeClass(user.role)}`}>
                          {getRoleIcon(user.role)} {user.role}
                        </span>
                      </td>
                      <td>{user.created_at ? new Date(user.created_at).toLocaleDateString() : 'N/A'}</td>
                      <td>
                        <div className="role-actions">
                          {user.role !== 'viewer' && (
                            <button
                              className="role-btn viewer-btn"
                              onClick={() => handleRoleChange(user.id, 'viewer', user.username)}
                              disabled={user.id === currentUser.id}
                              title="Downgrade to Viewer"
                            >
                              👁️ Viewer
                            </button>
                          )}
                          {user.role !== 'editor' && (
                            <button
                              className="role-btn editor-btn"
                              onClick={() => handleRoleChange(user.id, 'editor', user.username)}
                              disabled={user.id === currentUser.id}
                              title={user.role === 'viewer' ? 'Upgrade to Editor' : 'Downgrade to Editor'}
                            >
                              ✏️ Editor
                            </button>
                          )}
                          {user.role !== 'admin' && (
                            <button
                              className="role-btn admin-btn"
                              onClick={() => handleRoleChange(user.id, 'admin', user.username)}
                              title="Upgrade to Admin"
                            >
                              👑 Admin
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <div className="role-legend">
            <h3>Role Permissions:</h3>
            <div className="legend-items">
              <div className="legend-item">
                <span className="role-badge role-badge-viewer">👁️ Viewer</span>
                <p>Can view and download all documents</p>
              </div>
              <div className="legend-item">
                <span className="role-badge role-badge-editor">✏️ Editor</span>
                <p>Can view, download, upload new documents, and edit their own documents (version control)</p>
              </div>
              <div className="legend-item">
                <span className="role-badge role-badge-admin">👑 Admin</span>
                <p>Full access - can manage all documents, users, and system settings</p>
              </div>
            </div>
          </div>
        </>
      )}

      {/* File Permissions Tab */}
      {activeTab === 'filePermissions' && (
        <div className="file-permissions-section">
          <div className="file-permissions-card">
            <h3>Grant File-Level Permissions</h3>
            <p className="section-description">
              Give specific users access to individual files, even if they're normally viewers.
              For example: A viewer can edit a specific file.
            </p>

            <form onSubmit={handleGrantFilePermission} className="file-permission-form">
              <div className="form-group">
                <label>Select User:</label>
                <select
                  value={selectedUser}
                  onChange={(e) => setSelectedUser(e.target.value)}
                  disabled={grantingPermission}
                  required
                >
                  <option value="">-- Choose a user --</option>
                  {users.map(user => (
                    <option key={user.id} value={user.id}>
                      {user.username} ({user.role})
                    </option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label>Select File:</label>
                <select
                  value={selectedDocument}
                  onChange={(e) => setSelectedDocument(e.target.value)}
                  disabled={grantingPermission}
                  required
                >
                  <option value="">-- Choose a file --</option>
                  {documents.map(doc => (
                    <option key={doc.id} value={doc.id}>
                      {doc.filename}
                    </option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label>Permission Level:</label>
                <select
                  value={selectedPermission}
                  onChange={(e) => setSelectedPermission(e.target.value)}
                  disabled={grantingPermission}
                >
                  <option value="view">👁️ View Only</option>
                  <option value="edit">✏️ Edit</option>
                </select>
              </div>

              <button 
                type="submit" 
                disabled={grantingPermission || !selectedUser || !selectedDocument}
                className="grant-btn"
              >
                {grantingPermission ? 'Granting...' : '+ Grant Permission'}
              </button>
            </form>

            <div className="permission-info">
              <h4>How it works:</h4>
              <ul>
                <li>Select a user and a file</li>
                <li>Choose the permission level (View or Edit)</li>
                <li>Click "Grant Permission"</li>
                <li>The user will now have access to that file with the specified permissions</li>
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default AdminUserManagement;
