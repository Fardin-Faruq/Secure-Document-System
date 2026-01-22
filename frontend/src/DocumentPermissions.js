import React, { useState, useEffect } from 'react';
import axios from 'axios';

function DocumentPermissions({ documentId, token }) {
  const [permissions, setPermissions] = useState([]);
  const [users, setUsers] = useState([]);
  const [selectedUser, setSelectedUser] = useState('');
  const [selectedPermission, setSelectedPermission] = useState('view');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  const API_URL = 'http://localhost:5000/api';
  const headers = { Authorization: `Bearer ${token}` };

  useEffect(() => {
    fetchPermissions();
    fetchUsers();
  }, [documentId]);

  const fetchPermissions = async () => {
    try {
      const response = await axios.get(
        `${API_URL}/documents/${documentId}/permissions`,
        { headers }
      );
      setPermissions(response.data.permissions);
    } catch (error) {
      console.error('Error fetching permissions:', error);
    }
  };

  const fetchUsers = async () => {
    try {
      const response = await axios.get(`${API_URL}/users`, { headers });
      setUsers(response.data.users);
    } catch (error) {
      console.error('Error fetching users:', error);
    }
  };

  const handleGrantPermission = async (e) => {
    e.preventDefault();
    if (!selectedUser) {
      setMessage('Please select a user');
      return;
    }

    setLoading(true);
    try {
      await axios.post(
        `${API_URL}/documents/${documentId}/permissions`,
        { user_id: parseInt(selectedUser), permission: selectedPermission },
        { headers }
      );
      setMessage('Permission granted successfully!');
      setSelectedUser('');
      setSelectedPermission('view');
      fetchPermissions();
    } catch (error) {
      setMessage(error.response?.data?.message || 'Error granting permission');
    } finally {
      setLoading(false);
    }
  };

  const handleRevokePermission = async (userId) => {
    if (!window.confirm('Are you sure?')) return;

    try {
      await axios.delete(
        `${API_URL}/documents/${documentId}/permissions/${userId}`,
        { headers }
      );
      setMessage('Permission revoked!');
      fetchPermissions();
    } catch (error) {
      setMessage(error.response?.data?.message || 'Error revoking permission');
    }
  };

  return (
    <div className="permissions-container">
      <h3>Document Permissions</h3>
      
      <form onSubmit={handleGrantPermission} className="permission-form">
        <select
          value={selectedUser}
          onChange={(e) => setSelectedUser(e.target.value)}
          disabled={loading}
        >
          <option value="">Select user...</option>
          {users.map(u => (
            <option key={u.id} value={u.id}>{u.username} ({u.role})</option>
          ))}
        </select>

        <select
          value={selectedPermission}
          onChange={(e) => setSelectedPermission(e.target.value)}
          disabled={loading}
        >
          <option value="view">View Only</option>
          <option value="edit">Edit</option>
        </select>

        <button type="submit" disabled={loading}>Grant Permission</button>
      </form>

      {message && <div className="message success">{message}</div>}

      <div className="permissions-list">
        <h4>Current Permissions</h4>
        {permissions.length === 0 ? (
          <p>No permissions granted yet</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Username</th>
                <th>Permission</th>
                <th>Granted By</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {permissions.map(perm => (
                <tr key={perm.id}>
                  <td>{perm.username}</td>
                  <td><span className={`badge ${perm.permission}`}>{perm.permission}</span></td>
                  <td>{perm.granted_by}</td>
                  <td>
                    <button
                      className="btn-revoke"
                      onClick={() => handleRevokePermission(perm.user_id)}
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
  );
}

export default DocumentPermissions;
