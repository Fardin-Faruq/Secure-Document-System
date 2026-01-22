import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import './PermissionManager.css';
import { API_URL } from './api';
function PermissionManager({ document, onClose, onUpdate }) {
  const [permissions, setPermissions] = useState([]);
  const [users, setUsers] = useState([]);
  const [selectedUser, setSelectedUser] = useState('');
  const [selectedPermission, setSelectedPermission] = useState('view');
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState('');


  const getAuthHeaders = () => {
  const token = localStorage.getItem('token');
  return token ? { headers: { Authorization: `Bearer ${token}` } } : {};
};

  // ✅ Wrap fetchPermissions with useCallback
  const fetchPermissions = useCallback(async () => {
    try {
      const response = await axios.get(
        `${API_URL}/documents/${document.id}/permissions`,
        getAuthHeaders()
      );
      setPermissions(response.data.permissions);
    } catch (error) {
      console.error('Error fetching permissions:', error);
      setMessage('Failed to load permissions');
    } finally {
      setLoading(false);
    }
  }, [document.id, API_URL]); // ✅ Add dependencies

  // ✅ Wrap fetchUsers with useCallback
  const fetchUsers = useCallback(async () => {
    try {
      const response = await axios.get(`${API_URL}/users`, getAuthHeaders());
      setUsers(response.data.users);
    } catch (error) {
      console.error('Error fetching users:', error);
    }
  }, [API_URL]); // ✅ Add dependencies

  // ✅ Now useEffect dependencies are satisfied
  useEffect(() => {
    fetchPermissions();
    fetchUsers();
  }, [fetchPermissions, fetchUsers]); // ✅ Include them here

  const handleGrantPermission = async (e) => {
    e.preventDefault();
    
    if (!selectedUser) {
      setMessage('Please select a user');
      return;
    }

    try {
      await axios.post(
        `${API_URL}/documents/${document.id}/permissions`,
        {
          user_id: parseInt(selectedUser),
          permission_type: selectedPermission
        },
        getAuthHeaders()
      );
      
      setMessage('Permission granted successfully!');
      setSelectedUser('');
      fetchPermissions();
      if (onUpdate) onUpdate();
      
      setTimeout(() => setMessage(''), 3000);
    } catch (error) {
      setMessage(error.response?.data?.message || 'Failed to grant permission');
    }
  };

  const handleRevokePermission = async (permissionId) => {
    if (!window.confirm('Are you sure you want to revoke this permission?')) {
      return;
    }

    try {
      await axios.delete(
        `${API_URL}/documents/${document.id}/permissions/${permissionId}`,
        getAuthHeaders()
      );
      
      setMessage('Permission revoked successfully!');
      fetchPermissions();
      if (onUpdate) onUpdate();
      
      setTimeout(() => setMessage(''), 3000);
    } catch (error) {
      setMessage(error.response?.data?.message || 'Failed to revoke permission');
    }
  };

  const getPermissionBadgeClass = (type) => {
    switch (type) {
      case 'admin': return 'perm-badge-admin';
      case 'edit': return 'perm-badge-edit';
      case 'view': return 'perm-badge-view';
      default: return 'perm-badge-view';
    }
  };

  return (
    <div className="permission-modal-overlay" onClick={onClose}>
      <div className="permission-modal" onClick={(e) => e.stopPropagation()}>
        <div className="permission-header">
          <h2>Manage Permissions</h2>
          <button className="close-btn" onClick={onClose}>✕</button>
        </div>

        <div className="document-info">
          <p><strong>Document:</strong> {document.filename}</p>
        </div>

        {message && (
          <div className={`permission-message ${message.includes('success') ? 'success' : 'error'}`}>
            {message}
          </div>
        )}

        <div className="grant-permission-section">
          <h3>Grant New Permission</h3>
          <form onSubmit={handleGrantPermission} className="permission-form">
            <div className="form-row">
              <select 
                value={selectedUser} 
                onChange={(e) => setSelectedUser(e.target.value)}
                className="user-select"
              >
                <option value="">Select User</option>
                {users.map(user => (
                  <option key={user.id} value={user.id}>
                    {user.username} ({user.role})
                  </option>
                ))}
              </select>

              <select 
                value={selectedPermission} 
                onChange={(e) => setSelectedPermission(e.target.value)}
                className="permission-select"
              >
                <option value="view">View Only</option>
                <option value="edit">View & Edit</option>
                <option value="admin">Full Admin</option>
              </select>

              <button type="submit" className="grant-btn">
                Grant Permission
              </button>
            </div>
          </form>
        </div>

        <div className="current-permissions-section">
          <h3>Current Permissions</h3>
          {loading ? (
            <p className="loading-text">Loading permissions...</p>
          ) : permissions.length === 0 ? (
            <p className="no-permissions">No specific permissions granted yet.</p>
          ) : (
            <table className="permissions-table">
              <thead>
                <tr>
                  <th>User</th>
                  <th>Permission Level</th>
                  <th>Granted By</th>
                  <th>Granted At</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {permissions.map(perm => (
                  <tr key={perm.id}>
                    <td>{perm.user}</td>
                    <td>
                      <span className={`perm-badge ${getPermissionBadgeClass(perm.permission_type)}`}>
                        {perm.permission_type}
                      </span>
                    </td>
                    <td>{perm.granted_by}</td>
                    <td>{new Date(perm.granted_at).toLocaleString()}</td>
                    <td>
                      <button 
                        className="revoke-btn"
                        onClick={() => handleRevokePermission(perm.id)}
                      >
                        Revoke
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}

export default PermissionManager;