import React, { useState, useEffect } from 'react';
import axios from 'axios';

function ActivityDashboard({ token }) {
  const [logs, setLogs] = useState([]);
  const [filteredLogs, setFilteredLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedAction, setSelectedAction] = useState('');
  const [selectedDays, setSelectedDays] = useState(7);
  const [, setRefresh] = useState(0);

  const API_URL = 'http://localhost:5000/api';
  const headers = { Authorization: `Bearer ${token}` };

  // Live timestamp update interval
  useEffect(() => {
    const interval = setInterval(() => {
      setRefresh(prev => prev + 1);
    }, 60000); // Update every minute
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    fetchLogs();
  }, [selectedAction, selectedDays]);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      let url = `${API_URL}/logs?days=${selectedDays}`;
      if (selectedAction) {
        url += `&action=${selectedAction}`;
      }

      const response = await axios.get(url, { headers });
      setLogs(response.data.logs);
      setFilteredLogs(response.data.logs);
    } catch (error) {
      console.error('Error fetching logs:', error);
    } finally {
      setLoading(false);
    }
  };

  // Format time relative to now (e.g., "2 hours ago")
  const getRelativeTime = (dateString) => {
    const now = new Date();
    const logDate = new Date(dateString);
    const diffMs = now - logDate;
    const diffSecs = Math.floor(diffMs / 1000);
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffSecs < 60) return 'Just now';
    if (diffMins < 60) return `${diffMins} min${diffMins !== 1 ? 's' : ''} ago`;
    if (diffHours < 24) return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`;
    if (diffDays < 7) return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`;
    return logDate.toLocaleDateString();
  };

  const getActionColor = (action) => {
    const colors = {
      upload: '#4CAF50',
      download: '#2196F3',
      update: '#FF9800',
      delete: '#F44336',
      share: '#9C27B0',
      rollback: '#00BCD4',
      view: '#607D8B'
    };
    return colors[action] || '#999';
  };

  const stats = {
    total: logs.length,
    uploads: logs.filter(l => l.action === 'upload').length,
    downloads: logs.filter(l => l.action === 'download').length,
    updates: logs.filter(l => l.action === 'update').length,
    deletions: logs.filter(l => l.action === 'delete').length
  };

  return (
    <div className="activity-dashboard">
      <h2>Activity Dashboard</h2>

      {/* Statistics */}
      <div className="stats-grid">
        <div className="stat-card">
          <h4>Total Activities</h4>
          <p className="stat-value">{stats.total}</p>
        </div>
        <div className="stat-card">
          <h4>Uploads</h4>
          <p className="stat-value" style={{ color: getActionColor('upload') }}>
            {stats.uploads}
          </p>
        </div>
        <div className="stat-card">
          <h4>Downloads</h4>
          <p className="stat-value" style={{ color: getActionColor('download') }}>
            {stats.downloads}
          </p>
        </div>
        <div className="stat-card">
          <h4>Updates</h4>
          <p className="stat-value" style={{ color: getActionColor('update') }}>
            {stats.updates}
          </p>
        </div>
      </div>

      {/* Filters */}
      <div className="filters">
        <select
          value={selectedDays}
          onChange={(e) => setSelectedDays(e.target.value)}
        >
          <option value="1">Last 24 hours</option>
          <option value="7">Last 7 days</option>
          <option value="30">Last 30 days</option>
          <option value="90">Last 90 days</option>
        </select>

        <select
          value={selectedAction}
          onChange={(e) => setSelectedAction(e.target.value)}
        >
          <option value="">All actions</option>
          <option value="upload">Uploads</option>
          <option value="download">Downloads</option>
          <option value="update">Updates</option>
          <option value="delete">Deletions</option>
          <option value="share">Shares</option>
          <option value="rollback">Rollbacks</option>
        </select>
      </div>

      {/* Logs Table */}
      <div className="logs-table">
        <h3>Recent Activities</h3>
        {loading ? (
          <p>Loading...</p>
        ) : logs.length === 0 ? (
          <p>No activity found</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>User</th>
                <th>Document</th>
                <th>Action</th>
                <th>Timestamp</th>
                <th>IP Address</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log, idx) => (
                <tr key={log.id}>
                  <td><strong>{log.user}</strong></td>
                  <td>{log.document}</td>
                  <td>
                    <span
                      className="action-badge"
                      style={{ backgroundColor: getActionColor(log.action) }}
                    >
                      {log.action}
                    </span>
                  </td>
                  <td>{getRelativeTime(log.timestamp)}</td>
                  <td><code>{log.ip_address}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

export default ActivityDashboard;
