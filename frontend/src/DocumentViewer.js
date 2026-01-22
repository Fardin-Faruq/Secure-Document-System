import React, { useState, useEffect } from 'react';
import axios from 'axios';

function DocumentViewer({ documentId, filename, token }) {
  const [pdfDataUrl, setPdfDataUrl] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [fileType, setFileType] = useState('');

  const API_URL = 'http://localhost:5000/api';

  useEffect(() => {
    loadPDF();
  }, [documentId, token]);

  const loadPDF = async () => {
    try {
      setLoading(true);
      setError('');
      const ext = filename.split('.').pop().toLowerCase();
      setFileType(ext);

      // Only try to preview PDFs
      if (ext !== 'pdf') {
        setLoading(false);
        return;
      }

      const response = await axios.get(
        `${API_URL}/documents/${documentId}/download`,
        {
          headers: { Authorization: `Bearer ${token}` },
          responseType: 'arraybuffer'
        }
      );

      // Convert arraybuffer to base64
      const blob = new Blob([response.data], { type: 'application/pdf' });
      const reader = new FileReader();
      reader.onloadend = () => {
        setPdfDataUrl(reader.result);
        setLoading(false);
      };
      reader.onerror = () => {
        setError('Failed to read PDF file');
        setLoading(false);
      };
      reader.readAsDataURL(blob);
    } catch (err) {
      console.error('PDF Loading Error:', err);
      if (err.response?.status === 403) {
        setError('You do not have permission to view this document');
      } else {
        setError(err.response?.data?.message || 'Failed to load document');
      }
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="viewer-container"><p>📄 Loading PDF...</p></div>;
  }

  if (error) {
    return <div className="viewer-container error"><p>❌ {error}</p></div>;
  }

  // Only show PDF preview
  if (fileType === 'pdf' && pdfDataUrl) {
    return (
      <div className="viewer-container pdf-viewer">
        <embed
          src={pdfDataUrl}
          type="application/pdf"
          width="100%"
          height="600px"
          style={{ borderRadius: '8px' }}
        />
      </div>
    );
  }

  // For all other file types, show download option
  return (
    <div className="viewer-container">
      <div className="file-preview-message">
        <p>📁 This file type cannot be previewed in the browser</p>
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
