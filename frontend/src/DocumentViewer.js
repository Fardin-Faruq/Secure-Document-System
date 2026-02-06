import React, { useState, useEffect } from 'react';
import axios from 'axios';

function DocumentViewer({ documentId, filename, token }) {
  const [fileDataUrl, setFileDataUrl] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [fileType, setFileType] = useState('');

  const API_URL = 'http://localhost:5000/api';

  const getMimeType = (ext) => {
    const mimeTypes = {
      'pdf': 'application/pdf',
      'txt': 'text/plain',
      'doc': 'application/msword',
      'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'jpg': 'image/jpeg',
      'jpeg': 'image/jpeg',
      'png': 'image/png',
      'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'csv': 'text/csv'
    };
    return mimeTypes[ext] || 'application/octet-stream';
  };

  const loadFile = async () => {
    try {
      setLoading(true);
      setError('');
      const ext = filename.split('.').pop().toLowerCase();
      setFileType(ext);
      const mime = getMimeType(ext);

      const response = await axios.get(
        `${API_URL}/documents/${documentId}/download?preview=true`,
        {
          headers: { Authorization: `Bearer ${token}` },
          responseType: 'arraybuffer'
        }
      );

      // Convert arraybuffer to appropriate format
      const blob = new Blob([response.data], { type: mime });
      const reader = new FileReader();
      reader.onloadend = () => {
        setFileDataUrl(reader.result);
        setLoading(false);
      };
      reader.onerror = () => {
        setError('Failed to read file');
        setLoading(false);
      };
      reader.readAsDataURL(blob);
    } catch (err) {
      console.error('File Loading Error:', err);
      if (err.response?.status === 403) {
        setError('You do not have permission to view this document');
      } else {
        setError(err.response?.data?.message || 'Failed to load document');
      }
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFile();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [documentId, token]);

  if (loading) {
    return <div className="viewer-container"><p>📄 Loading document...</p></div>;
  }

  if (error) {
    return <div className="viewer-container error"><p>❌ {error}</p></div>;
  }

  // Show PDF preview
  if (fileType === 'pdf' && fileDataUrl) {
    return (
      <div className="viewer-container pdf-viewer">
        <embed
          src={fileDataUrl}
          type="application/pdf"
          width="100%"
          height="600px"
          style={{ borderRadius: '8px' }}
        />
      </div>
    );
  }

  // Show image preview
  if (['jpg', 'jpeg', 'png'].includes(fileType) && fileDataUrl) {
    return (
      <div className="viewer-container image-viewer">
        <img
          src={fileDataUrl}
          alt={filename}
          style={{
            maxWidth: '100%',
            maxHeight: '600px',
            borderRadius: '8px',
            objectFit: 'contain'
          }}
        />
      </div>
    );
  }

  // Show text preview
  if (fileType === 'txt' && fileDataUrl) {
    return (
      <div className="viewer-container text-viewer">
        <pre style={{
          maxHeight: '600px',
          overflow: 'auto',
          backgroundColor: '#f5f5f5',
          padding: '15px',
          borderRadius: '8px',
          fontSize: '13px',
          fontFamily: 'monospace'
        }}>
          <iframe
            src={fileDataUrl}
            style={{
              width: '100%',
              height: '600px',
              border: 'none',
              borderRadius: '8px'
            }}
            title={filename}
          />
        </pre>
      </div>
    );
  }

  // For file types that can be displayed in iframe (PDF, Office docs, etc)
  if (['pdf', 'doc', 'docx', 'xlsx', 'csv'].includes(fileType) && fileDataUrl) {
    return (
      <div className="viewer-container document-viewer">
        <iframe
          src={fileDataUrl}
          style={{
            width: '100%',
            height: '600px',
            border: 'none',
            borderRadius: '8px'
          }}
          title={filename}
        />
      </div>
    );
  }

  // Fallback: show download option for unsupported types
  return (
    <div className="viewer-container">
      <div className="file-preview-message">
        <p>📁 File preview not available in browser</p>
        <p>Click the button below to download and view the file:</p>
        <button
          onClick={() => {
            // Trigger download via API
            const link = document.createElement('a');
            link.href = `${API_URL}/documents/${documentId}/download`;
            link.setAttribute('download', filename);
            document.body.appendChild(link);
            link.click();
            link.remove();
          }}
          className="download-link-btn"
        >
          📥 Download {filename}
        </button>
      </div>
    </div>
  );
}

export default DocumentViewer;
