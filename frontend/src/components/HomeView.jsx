import { useState } from 'react';
import { Search, History, ShieldAlert } from 'lucide-react';
import './HomeView.css';

export default function HomeView({ onStartScan, onLoadReport }) {
  const [url, setUrl] = useState('');
  const [cookie, setCookie] = useState('');
  const [reportId, setReportId] = useState('');

  const handleScanSubmit = (e) => {
    e.preventDefault();
    if (url) onStartScan(url, cookie);
  };

  const handleLoadSubmit = (e) => {
    e.preventDefault();
    if (reportId) onLoadReport(reportId);
  };

  return (
    <div className="home-container fade-in">
      <div className="hero-section">
        <ShieldAlert size={64} className="hero-icon" />
        <h1 className="hero-title">Flux Security Engine</h1>
        <p className="hero-subtitle">Next-generation automated AI red teaming</p>
      </div>

      <div className="action-cards">
        {/* New Scan Card */}
        <div className="glass-panel action-card">
          <div className="card-header">
            <Search className="card-icon" />
            <h2>New Target Scan</h2>
          </div>
          <form onSubmit={handleScanSubmit} className="action-form">
            <div className="input-group">
              <label>Target URL</label>
              <input 
                type="url" 
                placeholder="https://example.com" 
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                required
              />
            </div>
            <div className="input-group">
              <label>Session Cookie (Optional)</label>
              <input 
                type="text" 
                placeholder="session_id=..." 
                value={cookie}
                onChange={(e) => setCookie(e.target.value)}
              />
            </div>
            <button type="submit" className="primary-btn">
              Initiate Attack Sequence
            </button>
          </form>
        </div>

        {/* Load Report Card */}
        <div className="glass-panel action-card">
          <div className="card-header">
            <History className="card-icon" />
            <h2>Load Previous Report</h2>
          </div>
          <form onSubmit={handleLoadSubmit} className="action-form">
            <div className="input-group">
              <label>Private Report UUID</label>
              <input 
                type="text" 
                placeholder="e.g. 550e8400-e29b-41d4-a716-446655440000" 
                value={reportId}
                onChange={(e) => setReportId(e.target.value)}
                required
              />
            </div>
            <button type="submit" className="secondary-btn">
              Retrieve Findings
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
