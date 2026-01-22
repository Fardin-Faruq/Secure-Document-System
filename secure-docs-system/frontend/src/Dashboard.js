import React, { useState, useEffect } from 'react';
import { useAuth } from './AuthContext';
import DocumentPermissions from './DocumentPermissions';
import DocumentVersioning from './DocumentVersioning';
import DocumentSharing from './DocumentSharing';
import DocumentViewer from './DocumentViewer';
import ActivityDashboard from './ActivityDashboard';
import axios from 'axios';
import './Dashboard.css';

function Dashboard() {
  const { user, logout } = useAuth();
  const [documents, setDocuments] = useState([]);
  const [logs, setLogs] = useState([]);
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [message, setMessage] = useState('');
  const [messageType, setMessageType] = useState(''); // 'success' or 'error'
  const [activeTab, setActiveTab] = useState('documents');
  const [selectedDocument, setSelectedDocument] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [modalTab, setModalTab] = useState('details');
  const [, setRefresh] = useState(0);

  const API_URL = 'http://localhost:5000/api';

  // Live timestamp update interval
  useEffect(() => {
    const interval = setInterval(() => {
      setRefresh(prev => prev + 1);
    }, 60000); // Update every minute
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    fetchDocuments();
    if (user?.role === 'admin') {
      fetchLogs();
    }
  }, [user]);

  const getAuthHeaders = () => ({
    headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
  });

  // Format time relative to now (e.g., "2 hours ago") with IST timezone
  const getRelativeTime = (dateString) => {
    const now = new Date();
    const uploadDate = new Date(dateString);
    const diffMs = now - uploadDate;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins} min${diffMins !== 1 ? 's' : ''} ago`;
    if (diffHours < 24) return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`;
    if (diffDays < 7) return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`;
    
    // Convert to IST (GMT+5:30)
    return uploadDate.toLocaleString('en-IN', { 
      year: 'numeric', 
      month: 'short', 
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      timeZone: 'Asia/Kolkata'
    });
  };

  const fetchDocuments = async () => {
    try {
      const response = await axios.get(`${API_URL}/documents`, getAuthHeaders());
      setDocuments(response.data.documents);
    } catch (error) {
      console.error('Error fetching documents:', error);
    }
  };

  const fetchLogs = async () => {
    try {
      const response = await axios.get(`${API_URL}/logs`, getAuthHeaders());
      setLogs(response.data.logs);
    } catch (error) {
      console.error('Error fetching logs:', error);
    }
  };

  const handleFileChange = (e) => {
    setSelectedFile(e.target.files[0]);
    setMessage('');
  };

  const handleUpload = async (e) => {
    e.preventDefault();
    
    if (!selectedFile) {
      setMessage('Please select a file!');
      return;
    }

    setUploading(true);
    const formData = new FormData();
    formData.append('file', selectedFile);

    // ✅ Generate idempotency key to prevent duplicate uploads from retries
    const idempotencyKey = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    try {
      await axios.post(
        `${API_URL}/documents/upload`,
        formData,
        {
          headers: {
            Authorization: `Bearer ${localStorage.getItem('token')}`,
            'Content-Type': 'multipart/form-data',
            'X-Idempotency-Key': idempotencyKey
          }
        }
      );
      
      setMessage('✅ File uploaded successfully!');
      setMessageType('success');
      setSelectedFile(null);
      document.getElementById('file-input').value = '';
      fetchDocuments();
      if (user?.role === 'admin') {
        fetchLogs();
      }
    } catch (error) {
      setMessage(error.response?.data?.message || 'Upload failed!');
      setMessageType('error');
    } finally {
      setUploading(false);
    }
  };

  const handleDownload = async (documentId, filename) => {
    try {
      const response = await axios.get(
        `${API_URL}/documents/${documentId}/download`,
        {
          ...getAuthHeaders(),
          responseType: 'blob'
        }
      );

      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', filename);
      document.body.appendChild(link);
      link.click();
      link.remove();
      
      if (user?.role === 'admin') {
        fetchLogs();
      }
    } catch (error) {
      // Parse error response properly
      let errorMessage = 'Unknown error';
      
      if (error.response?.data) {
        // If it's JSON, parse it
        if (error.response.data instanceof Blob) {
          try {
            const json = JSON.parse(await error.response.data.text());
            errorMessage = json.message || 'Unknown error';
          } catch {
            errorMessage = 'Unknown error';
          }
        } else if (typeof error.response.data === 'object') {
          errorMessage = error.response.data.message || 'Unknown error';
        }
      }
      
      setMessage('❌ ' + errorMessage);
      setMessageType('error');
    }
  };

  const handleDelete = async (documentId) => {
    if (!window.confirm('Are you sure you want to delete this document?')) {
      return;
    }

    try {
      await axios.delete(
        `${API_URL}/documents/${documentId}`,
        getAuthHeaders()
      );
      
      setMessage('✅ Document deleted successfully!');
      setMessageType('success');
      fetchDocuments();
      if (user?.role === 'admin') {
        fetchLogs();
      }
    } catch (error) {
      setMessage('❌ ' + (error.response?.data?.message || 'Delete failed!'));
      setMessageType('error');
    }
  };

  const handleViewDetails = (doc) => {
    setSelectedDocument(doc);
    setShowModal(true);
  };

  const getRoleColor = (role) => {
    switch(role) {
      case 'admin': return '#dc3545';
      case 'editor': return '#ffc107';
      case 'viewer': return '#28a745';
      default: return '#6c757d';
    }
  };

  const getRolePermissions = (role) => {
    switch(role) {
      case 'admin':
        return ['View Documents', 'Upload Documents', 'Delete Documents', 'View Access Logs'];
      case 'editor':
        return ['View Documents', 'Upload Documents'];
      case 'viewer':
        return ['View Documents', 'Download Documents'];
      default:
        return [];
    }
  };

  const canUpload = user?.role === 'admin' || user?.role === 'editor';
  const canDelete = user?.role === 'admin';

  return (
    <div className="dashboard">
      <nav className="navbar">
        <h1>🔒 Secure Document System</h1>
        <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
          <span style={{ fontSize: '14px' }}>
            {user?.username} ({user?.role})
          </span>
          <button onClick={logout} className="logout-btn">Logout</button>
        </div>
      </nav>

      <div className="dashboard-content">
        <div className="user-info-card">
          <h2>Welcome, {user?.username}!</h2>
          <div className="role-badge" style={{ backgroundColor: getRoleColor(user?.role) }}>
            {user?.role?.toUpperCase()}
          </div>
          
          <div className="permissions">
            <h3>Your Permissions:</h3>
            <ul>
              {getRolePermissions(user?.role).map((permission, index) => (
                <li key={index}>✓ {permission}</li>
              ))}
            </ul>
          </div>

          <div className="timezone-info">
            <p style={{ fontSize: '12px', color: '#666', marginTop: '15px' }}>
              🕐 Current IST Time: {new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })}
            </p>
          </div>
        </div>

        <div className="tabs">
          <button
            className={`tab ${activeTab === 'documents' ? 'active' : ''}`}
            onClick={() => setActiveTab('documents')}
          >
            📁 Documents
          </button>
          {canDelete && (
            <button
              className={`tab ${activeTab === 'logs' ? 'active' : ''}`}
              onClick={() => setActiveTab('logs')}
            >
              📊 Activity Logs
            </button>
          )}
        </div>

        {activeTab === 'documents' && (
          <>
            {canUpload && (
              <div className="upload-section">
                <h2>Upload Document</h2>
                <form onSubmit={handleUpload}>
                  <div className="file-input-wrapper">
                    <input
                      type="file"
                      id="file-input"
                      onChange={handleFileChange}
                      accept=".txt,.pdf,.doc,.docx,.jpg,.jpeg,.png,.xlsx,.csv"
                    />
                    <label htmlFor="file-input" className="file-label">
                      {selectedFile ? selectedFile.name : 'Choose File'}
                    </label>
                  </div>
                  <button
                    type="submit"
                    className="upload-btn"
                    disabled={uploading || !selectedFile}
                  >
                    {uploading ? 'Uploading...' : 'Upload'}
                  </button>
                </form>
                {message && <div className={`upload-message ${messageType}`}>{message}</div>}
              </div>
            )}

            <div className="documents-section">
              <h2>All Documents ({documents.length})</h2>
              {documents.length === 0 ? (
                <p className="no-documents">No documents uploaded yet.</p>
              ) : (
                <div className="documents-grid">
                  {documents.map((doc) => (
                    <div key={doc.id} className="document-card">
                      <div className="doc-icon">
                        {doc.file_type === 'pdf' && '📄'}
                        {['jpg', 'jpeg', 'png'].includes(doc.file_type) && '🖼️'}
                        {['doc', 'docx'].includes(doc.file_type) && '📝'}
                        {['xlsx', 'csv'].includes(doc.file_type) && '📊'}
                        {doc.file_type === 'txt' && '📃'}
                      </div>
                      <div className="doc-info">
                        <h3>{doc.filename}</h3>
                        <p className="doc-meta">
                          Size: {(doc.file_size / 1024).toFixed(2)} KB
                        </p>
                        <p className="doc-meta">
                          Uploaded by: {doc.uploaded_by}
                        </p>
                        <p className="doc-meta">
                          {getRelativeTime(doc.upload_date)}
                        </p>
                      </div>
                      <div className="doc-actions">
                        <button
                          onClick={() => handleViewDetails(doc)}
                          className="action-btn info-btn"
                          title="View details, permissions, versions, share"
                        >
                          ℹ️ Details
                        </button>
                        <button
                          onClick={() => handleDownload(doc.id, doc.filename)}
                          className="action-btn download-btn"
                        >
                          ⬇️ Download
                        </button>
                        {canDelete && (
                          <button
                            onClick={() => handleDelete(doc.id)}
                            className="action-btn delete-btn"
                          >
                            🗑️ Delete
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </>
        )}

        {activeTab === 'logs' && canDelete && (
          <ActivityDashboard token={localStorage.getItem('token')} />
        )}
      </div>

      {/* Document Details Modal */}
      {showModal && selectedDocument && (
        <div className="modal-overlay" onClick={() => setShowModal(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <button className="modal-close" onClick={() => setShowModal(false)}>✕</button>
            <h2>{selectedDocument.filename}</h2>
            
            <div className="modal-tabs">
              <button
                className={`modal-tab-btn ${modalTab === 'preview' ? 'active' : ''}`}
                onClick={() => setModalTab('preview')}
              >
                Preview
              </button>
              <button
                className={`modal-tab-btn ${modalTab === 'details' ? 'active' : ''}`}
                onClick={() => setModalTab('details')}
              >
                Details
              </button>
              <button
                className={`modal-tab-btn ${modalTab === 'permissions' ? 'active' : ''}`}
                onClick={() => setModalTab('permissions')}
              >
                Permissions
              </button>
              <button
                className={`modal-tab-btn ${modalTab === 'versions' ? 'active' : ''}`}
                onClick={() => setModalTab('versions')}
              >
                Versions
              </button>
              <button
                className={`modal-tab-btn ${modalTab === 'share' ? 'active' : ''}`}
                onClick={() => setModalTab('share')}
              >
                Share
              </button>
            </div>

            <div className="modal-content">
              {/* Preview Tab */}
              {modalTab === 'preview' && (
                <DocumentViewer
                  documentId={selectedDocument.id}
                  filename={selectedDocument.filename}
                  token={localStorage.getItem('token')}
                />
              )}

              {/* Details Tab */}
              {modalTab === 'details' && (
                <div className="tab-panel">
                  <h3>Document Details</h3>
                  <p><strong>File Type:</strong> {selectedDocument.file_type}</p>
                  <p><strong>File Size:</strong> {(selectedDocument.file_size / 1024).toFixed(2)} KB</p>
                  <p><strong>Uploaded By:</strong> {selectedDocument.uploaded_by}</p>
                  <p><strong>Upload Date:</strong> {new Date(selectedDocument.upload_date).toLocaleString()}</p>
                </div>
              )}

              {/* Permissions Tab */}
              {modalTab === 'permissions' && (
                <DocumentPermissions
                  documentId={selectedDocument.id}
                  token={localStorage.getItem('token')}
                />
              )}

              {/* Versioning Tab */}
              {modalTab === 'versions' && (
                <DocumentVersioning
                  documentId={selectedDocument.id}
                  token={localStorage.getItem('token')}
                  userRole={user?.role}
                  documentOwnerId={selectedDocument.uploaded_by_id || selectedDocument.uploaded_by}
                  userId={user?.id}
                />
              )}

              {/* Sharing Tab */}
              {modalTab === 'share' && (
                <DocumentSharing
                  documentId={selectedDocument.id}
                  token={localStorage.getItem('token')}
                />
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default Dashboard;