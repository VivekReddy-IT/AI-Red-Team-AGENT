import { useState } from 'react';
import HomeView from './components/HomeView';
import ScanningView from './components/ScanningView';
import ReportView from './components/ReportView';
import { scanUrl, fetchReport } from './api';

export default function App() {
  const [view, setView] = useState('home'); // home, scanning, report
  const [reportData, setReportData] = useState(null);
  const [currentReportId, setCurrentReportId] = useState(null);
  const [scanTarget, setScanTarget] = useState('');
  const [error, setError] = useState(null);

  const navHome = () => {
    setView('home');
    setReportData(null);
    setCurrentReportId(null);
    setError(null);
  };

  const handleStartScan = async (url, cookie) => {
    try {
      setError(null);
      setScanTarget(url);
      setView('scanning');
      
      const result = await scanUrl(url, cookie);
      setReportData(result);
      setCurrentReportId(result.report_id);
      setView('report');
    } catch (err) {
      setError(err.message);
      setView('home');
    }
  };

  const handleLoadReport = async (reportId) => {
    try {
      setError(null);
      const loadingToast = document.createElement('div');
      loadingToast.className = 'toast loading';
      loadingToast.innerText = 'Loading report...';
      document.body.appendChild(loadingToast);
      
      const result = await fetchReport(reportId);
      setReportData(result);
      setCurrentReportId(reportId);
      setView('report');
      
      document.body.removeChild(loadingToast);
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="app-layout">
      {/* Top Navbar */}
      <header className="app-header glass-panel">
        <div className="logo" onClick={navHome} style={{ cursor: 'pointer' }}>
          <div className="logo-pulse"></div>
          <h2>Flux</h2>
        </div>
      </header>

      {/* Error Toast Container */}
      {error && (
        <div className="error-toast fade-in">
          <span>{error}</span>
          <button onClick={() => setError(null)}>×</button>
        </div>
      )}

      {/* Main Content Area */}
      <main className="app-main">
        {view === 'home' && (
          <HomeView 
            onStartScan={handleStartScan} 
            onLoadReport={handleLoadReport} 
          />
        )}
        
        {view === 'scanning' && (
          <ScanningView url={scanTarget} />
        )}
        
        {view === 'report' && reportData && (
          <ReportView 
            report={reportData} 
            reportId={currentReportId} 
            onBack={navHome} 
          />
        )}
      </main>
    </div>
  );
}
