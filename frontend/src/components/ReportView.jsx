import { useState } from 'react';
import { ShieldCheck, ShieldAlert, Cpu, ChevronDown, CheckCircle2, AlertTriangle, ArrowLeft } from 'lucide-react';
import './ReportView.css';

export default function ReportView({ report, reportId, onBack }) {
  const [expandedIndex, setExpandedIndex] = useState(null);

  const toggleAccordion = (index) => {
    setExpandedIndex(expandedIndex === index ? null : index);
  };

  const getSeverityData = (severity) => {
    const sev = (severity || 'Low').toLowerCase();
    if (sev === 'high' || sev === 'critical') return { class: 'sev-high', icon: ShieldAlert, label: 'High Severity' };
    if (sev === 'medium') return { class: 'sev-medium', icon: AlertTriangle, label: 'Medium Severity' };
    return { class: 'sev-low', icon: ShieldCheck, label: 'Low Severity' };
  };

  const vulns = report.vulnerabilities || [];

  return (
    <div className="report-container fade-in">
      <button className="back-btn" onClick={onBack}>
        <ArrowLeft size={16} /> Back to Dashboard
      </button>

      <div className="report-header glass-panel">
        <div className="header-content">
          <h1>Threat Intelligence Report</h1>
          <a href={report.url} target="_blank" rel="noreferrer" className="target-url">
            {report.url}
          </a>
          <div className="report-meta">
            <span className="pill uuid-pill">UUID: {reportId || report.report_id || 'N/A'}</span>
            <span className="pill forms-pill">Forms Analyzed: {report.forms_found || 0}</span>
            <span className="pill findings-pill">Total Findings: {vulns.length}</span>
          </div>
        </div>
      </div>

      <div className="findings-section">
        <h2 className="section-title">Vulnerability Mapping</h2>
        {vulns.length === 0 ? (
          <div className="no-findings glass-panel">
            <CheckCircle2 color="#22c55e" size={48} />
            <h3>No major vulnerabilities detected</h3>
            <p>Our scanners did not find any critical injection vectors.</p>
          </div>
        ) : (
          <div className="accordion-list">
            {vulns.map((vuln, index) => {
              const sevData = getSeverityData(vuln.severity);
              const SevIcon = sevData.icon;
              const isExpanded = expandedIndex === index;

              return (
                <div key={index} className={`vuln-card glass-panel ${isExpanded ? 'expanded' : ''} ${sevData.class}`}>
                  <div className="vuln-header" onClick={() => toggleAccordion(index)}>
                    <div className="vuln-primary-info">
                      <SevIcon className="sev-icon" />
                      <h3 className="vuln-title">{vuln.type || 'Unknown Vulnerability'}</h3>
                      {vuln.ml_confidence !== undefined && (
                        <span className="pill ml-pill" style={{ marginLeft: '1rem', background: 'rgba(168, 85, 247, 0.15)', color: '#d8b4fe', fontSize: '0.75rem' }}>
                          <Cpu size={12} style={{ display: 'inline', marginRight: '4px', verticalAlign: 'middle' }} />
                          ML Confidence: {vuln.ml_confidence}%
                        </span>
                      )}
                    </div>
                    <div className="vuln-secondary-info">
                      <span className={`sev-badge ${sevData.class}`}>{sevData.label}</span>
                      <ChevronDown className={`expand-icon ${isExpanded ? 'rotated' : ''}`} />
                    </div>
                  </div>
                  
                  {isExpanded && (
                    <div className="vuln-body">
                      {vuln.description && (
                         <div className="vuln-detail">
                           <h4>Description</h4>
                           <p>{vuln.description}</p>
                         </div>
                      )}
                      
                      {vuln.target && (
                         <div className="vuln-detail">
                           <h4>Target Endpoint</h4>
                           <code>{vuln.target}</code>
                         </div>
                      )}

                      {vuln.payload && (
                         <div className="vuln-detail">
                           <h4>Attack Payload</h4>
                           <code>{vuln.payload}</code>
                         </div>
                      )}

                      {vuln.ai_explanation && (
                        <div className="ai-explanation">
                          <h4 className="ai-title"><Cpu size={18} /> Claude Intelligence Analysis</h4>
                          <div className="ai-content">
                            {vuln.ai_explanation}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
