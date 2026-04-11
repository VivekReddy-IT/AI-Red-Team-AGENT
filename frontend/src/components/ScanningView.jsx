import { useEffect, useState } from 'react';
import { Activity } from 'lucide-react';
import './ScanningView.css';

export default function ScanningView({ url }) {
  const [statusText, setStatusText] = useState('Initializing engines...');

  useEffect(() => {
    const statuses = [
      'Establishing connection...',
      'Deep spidering target...',
      'Mapping attack surface...',
      'Injecting SQLi payloads...',
      'Hunting for XSS...',
      'Analyzing security headers...',
      'Testing command execution...',
      'Awaiting AI explanations...'
    ];
    let i = 0;
    const timer = setInterval(() => {
      i = (i + 1) % statuses.length;
      setStatusText(statuses[i]);
    }, 2500);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="scanning-container fade-in">
      <div className="radar-wrapper">
        <div className="radar"></div>
        <Activity size={48} className="pulse-icon" />
      </div>
      
      <h2 className="scanning-title">Scanning in Progress</h2>
      <p className="scanning-target">{url}</p>
      
      <div className="status-indicator">
        <span className="spinner"></span>
        <p className="status-text">{statusText}</p>
      </div>
    </div>
  );
}
