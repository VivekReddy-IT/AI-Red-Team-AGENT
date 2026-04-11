// api.js
const API_BASE = 'http://127.0.0.1:8000';

export async function scanUrl(url) {
  const response = await fetch(`${API_BASE}/scan`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ url }),
  });
  
  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    throw new Error(errorBody.detail || 'Failed to scan target');
  }
  
  return response.json();
}

export async function fetchReport(reportId) {
  const response = await fetch(`${API_BASE}/report/${reportId}`);
  
  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    throw new Error(errorBody.detail || 'Failed to load report');
  }
  
  return response.json();
}
