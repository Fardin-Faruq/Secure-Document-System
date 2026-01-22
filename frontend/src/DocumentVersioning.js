import React, { useState, useEffect } from 'react';
import axios from 'axios';

function DocumentVersioning({ documentId, token, userRole, documentOwnerId, userId }) {
  const [versions, setVersions] = useState([]);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [messageType, setMessageType] = useState('');
  const [file, setFile] = useState(null);
  const [description, setDescription] = useState('');

  const API_URL = 'http://localhost:5000/api';
  const headers = { Authorization: `Bearer ${token}` };

  // Check if user can edit
  const canEdit = userRole === 'admin' || (userRole === 'editor' && userId === documentOwnerId);
  const isAdmin = userRole === 'admin';

  useEffect(() => {
    fetchVersions();
  }, [documentId]);

  const fetchVersions = async () => {
    try {
      const response = await axios.get(
        `${API_URL}/documents/${documentId}/versions`,
        { headers }
      );
      setVersions(response.data.versions);
    } catch (error) {
      console.error('Error fetching versions:', error);
      setMessage('❌ ' + (error.response?.data?.message || 'Failed to load versions'));
      setMessageType('error');
    }
  };

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
  };

  const handleUpdateDocument = async (e) => {
    e.preventDefault();
    if (!file) {
      setMessage('Please select a file');
      setMessageType('error');
      return;
    }

    if (!canEdit && !isAdmin) {
      setMessage('❌ You do not have permission to edit this document');
      setMessageType('error');
      return;
    }

    setLoading(true);
    const formData = new FormData();
    formData.append('file', file);
    formData.append('description', description);

    try {
      await axios.post(
        `${API_URL}/documents/${documentId}/update`,
        formData,
        {
          headers: {
            ...headers,
            'Content-Type': 'multipart/form-data'
          }
        }
      );
      setMessage('✅ Document updated successfully!');
      setMessageType('success');
      setFile(null);
      setDescription('');
      fetchVersions();
    } catch (error) {
      setMessage('❌ ' + (error.response?.data?.message || 'Error updating document'));
      setMessageType('error');
    } finally {
      setLoading(false);
    }
  };

  const handleRollback = async (versionId) => {
    if (!window.confirm('Rollback to this version? This will create a new version.')) return;

    if (!canEdit && !isAdmin) {
      setMessage('❌ You do not have permission to rollback this document');
      setMessageType('error');
      return;
    }

    try {
      await axios.post(
        `${API_URL}/documents/${documentId}/rollback/${versionId}`,
        {},
        { headers }
      );
      setMessage('✅ Document rolled back successfully!');
      setMessageType('success');
      fetchVersions();
    } catch (error) {
      setMessage('❌ ' + (error.response?.data?.message || 'Error rolling back'));
      setMessageType('error');
    }
  };

  return (
    <div className="versioning-container">
      <h3>Document Versions</h3>

      {!canEdit && !isAdmin && (
        <div className="permission-warning">
          <p>⚠️ You do not have permission to edit this document. Only the owner and admins can update versions.</p>
        </div>
      )}

      {(canEdit || isAdmin) && (
        <form onSubmit={handleUpdateDocument} className="update-form">
          <input
            type="file"
            onChange={handleFileChange}
            disabled={loading}
          />
          <input
            type="text"
            placeholder="Version description (optional)"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            disabled={loading}
          />
          <button type="submit" disabled={loading || !file}>
            {loading ? 'Updating...' : 'Update Document'}
          </button>
        </form>
      )}

      {message && <div className={`message ${messageType}`}>{message}</div>}

      <div className="versions-list">
        <h4>Version History</h4>
        {versions.length === 0 ? (
          <p>No versions available</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Version</th>
                <th>Description</th>
                <th>Uploaded By</th>
                <th>Date</th>
                <th>Size</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {versions.map((ver, idx) => (
                <tr key={ver.id} className={idx === 0 ? 'current-version' : ''}>
                  <td><strong>v{ver.version_number}</strong></td>
                  <td>{ver.change_description}</td>
                  <td>{ver.uploaded_by}</td>
                  <td>{new Date(ver.created_at).toLocaleDateString()}</td>
                  <td>{(ver.file_size / 1024).toFixed(2)} KB</td>
                  <td>
                    {idx !== 0 && (canEdit || isAdmin) && (
                      <button
                        className="btn-rollback"
                        onClick={() => handleRollback(ver.id)}
                      >
                        Rollback
                      </button>
                    )}
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

export default DocumentVersioning;
