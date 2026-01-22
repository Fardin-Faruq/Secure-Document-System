import React, { useState, useEffect } from 'react';
import axios from 'axios';

function DocumentSharing({ documentId, token }) {
  const [shareLinks, setShareLinks] = useState([]);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [expiresInHours, setExpiresInHours] = useState(24);
  const [downloadLimit, setDownloadLimit] = useState('');

  const API_URL = 'http://localhost:5000/api';
  const headers = { Authorization: `Bearer ${token}` };

  useEffect(() => {
    fetchShareLinks();
  }, [documentId]);

  const fetchShareLinks = async () => {
    try {
      const response = await axios.get(
        `${API_URL}/documents/${documentId}/shares`,
        { headers }
      );
      setShareLinks(response.data.share_links);
    } catch (error) {
      console.error('Error fetching share links:', error);
    }
  };

  const handleCreateShareLink = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await axios.post(
        `${API_URL}/documents/${documentId}/share`,
        {
          expires_in_hours: parseInt(expiresInHours),
          download_limit: downloadLimit ? parseInt(downloadLimit) : null
        },
        { headers }
      );

      setMessage('Share link created successfully!');
      setExpiresInHours(24);
      setDownloadLimit('');
      fetchShareLinks();
    } catch (error) {
      setMessage(error.response?.data?.message || 'Error creating share link');
    } finally {
      setLoading(false);
    }
  };

  const handleRevokeLink = async (shareId) => {
    if (!window.confirm('Revoke this share link?')) return;

    try {
      await axios.delete(
        `${API_URL}/share/${shareId}`,
        { headers }
      );
      setMessage('Share link revoked!');
      fetchShareLinks();
    } catch (error) {
      setMessage(error.response?.data?.message || 'Error revoking link');
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setMessage('Copied to clipboard!');
    setTimeout(() => setMessage(''), 2000);
  };

  const isExpired = (expiresAt) => new Date(expiresAt) < new Date();

  return (
    <div className="sharing-container">
      <h3>Share Document</h3>

      <form onSubmit={handleCreateShareLink} className="share-form">
        <div className="form-group">
          <label>Expires in (hours):</label>
          <input
            type="number"
            value={expiresInHours}
            onChange={(e) => setExpiresInHours(e.target.value)}
            min="1"
            max="720"
            disabled={loading}
          />
        </div>

        <div className="form-group">
          <label>Download limit (leave blank for unlimited):</label>
          <input
            type="number"
            value={downloadLimit}
            onChange={(e) => setDownloadLimit(e.target.value)}
            min="1"
            disabled={loading}
            placeholder="Unlimited"
          />
        </div>

        <button type="submit" disabled={loading}>
          {loading ? 'Creating...' : 'Create Share Link'}
        </button>
      </form>

      {message && <div className="message success">{message}</div>}

      <div className="share-links-list">
        <h4>Active Share Links</h4>
        {shareLinks.length === 0 ? (
          <p>No share links created yet</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Link</th>
                <th>Expires</th>
                <th>Downloads</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {shareLinks.map(link => (
                <tr key={link.id} className={isExpired(link.expires_at) ? 'expired' : ''}>
                  <td>
                    <code>{link.token.substring(0, 20)}...</code>
                    <button
                      className="btn-copy"
                      onClick={() => copyToClipboard(
                        `${window.location.origin}/api/documents/shared/${link.token}`
                      )}
                      title="Copy full link"
                    >
                      📋
                    </button>
                  </td>
                  <td>{new Date(link.expires_at).toLocaleDateString()}</td>
                  <td>
                    {link.download_limit
                      ? `${link.download_count}/${link.download_limit}`
                      : `${link.download_count}/∞`}
                  </td>
                  <td>
                    <span className={`badge ${link.is_active && !isExpired(link.expires_at) ? 'active' : 'inactive'}`}>
                      {link.is_active && !isExpired(link.expires_at) ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                  <td>
                    <button
                      className="btn-revoke"
                      onClick={() => handleRevokeLink(link.id)}
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

export default DocumentSharing;
