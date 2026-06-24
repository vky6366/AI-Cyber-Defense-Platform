const API_BASE = window.location.origin.includes('localhost') ? 'http://localhost:8000' : '';

// DOM Elements
const sysStatus = document.getElementById('system-status');
const sysStatusText = document.getElementById('status-text');
const logInput = document.getElementById('log-input');
const analyzeBtn = document.getElementById('analyze-btn');
const analyzeResult = document.getElementById('analyze-result');
const incidentsList = document.getElementById('incidents-list');
const refreshBtn = document.getElementById('refresh-btn');

// Modal Elements
const modal = document.getElementById('incident-modal');
const closeModal = document.getElementById('close-modal');
const modalTitle = document.getElementById('modal-title');
const modalSeverity = document.getElementById('modal-severity');
const modalStatus = document.getElementById('modal-status');
const modalReport = document.getElementById('modal-report');
const approvalSection = document.getElementById('approval-section');
const analystNotes = document.getElementById('analyst-notes');
const approveBtn = document.getElementById('approve-btn');
const rejectBtn = document.getElementById('reject-btn');

let currentIncidentId = null;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    checkHealth();
    fetchIncidents();
    setInterval(checkHealth, 30000); // Check health every 30s
});

// Health Check
async function checkHealth() {
    try {
        const res = await fetch(`${API_BASE}/health`);
        if (res.ok) {
            sysStatus.className = 'dot active';
            sysStatusText.textContent = 'System Active';
        } else {
            throw new Error('Not OK');
        }
    } catch (e) {
        sysStatus.className = 'dot';
        sysStatus.style.background = '#ef4444';
        sysStatus.style.boxShadow = 'none';
        sysStatusText.textContent = 'System Offline';
    }
}

// Analyze Logs
analyzeBtn.addEventListener('click', async () => {
    const rawData = logInput.value.trim();
    if (!rawData) return;

    let payload;
    try {
        payload = JSON.parse(rawData);
        if (!Array.isArray(payload)) {
            payload = [payload];
        }
    } catch (e) {
        analyzeResult.style.color = 'var(--danger)';
        analyzeResult.textContent = 'Invalid JSON format.';
        return;
    }

    setLoading(analyzeBtn, true);
    analyzeResult.textContent = '';

    try {
        const res = await fetch(`${API_BASE}/analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ logs: payload })
        });
        const data = await res.json();
        
        if (res.ok) {
            analyzeResult.style.color = 'var(--success)';
            analyzeResult.textContent = `Analysis complete. Severity: ${data.severity}`;
            fetchIncidents();
        } else {
            throw new Error(data.detail || 'Analysis failed');
        }
    } catch (e) {
        analyzeResult.style.color = 'var(--danger)';
        analyzeResult.textContent = e.message;
    } finally {
        setLoading(analyzeBtn, false);
    }
});

// Fetch Incidents
refreshBtn.addEventListener('click', fetchIncidents);

async function fetchIncidents() {
    try {
        const res = await fetch(`${API_BASE}/incidents`);
        const incidents = await res.json();
        
        incidentsList.innerHTML = '';
        if (incidents.length === 0) {
            incidentsList.innerHTML = '<div class="empty-state">No incidents recorded.</div>';
            return;
        }

        // Sort: pending first, then by ID (placeholder for timestamp if existed)
        incidents.sort((a, b) => a.status === 'pending_approval' ? -1 : 1);

        incidents.forEach(inc => {
            const el = document.createElement('div');
            el.className = 'incident-item';
            el.innerHTML = `
                <div>
                    <div class="incident-id">#${inc.incident_id.split('-')[0]}</div>
                    <div style="font-weight: 600;">Threat Detected</div>
                </div>
                <div style="display:flex; gap: 8px;">
                    <span class="badge severity-${inc.severity.toLowerCase()}">${inc.severity}</span>
                    <span class="badge" style="background: rgba(255,255,255,0.1)">${inc.status.replace('_', ' ')}</span>
                </div>
            `;
            el.addEventListener('click', () => openModal(inc.incident_id));
            incidentsList.appendChild(el);
        });
    } catch (e) {
        console.error('Failed to fetch incidents', e);
    }
}

// Modal Logic
async function openModal(id) {
    currentIncidentId = id;
    modalTitle.textContent = `Incident #${id.split('-')[0]}`;
    modalSeverity.textContent = 'Loading...';
    modalStatus.textContent = '';
    modalReport.textContent = 'Fetching details...';
    approvalSection.style.display = 'none';
    modal.style.display = 'flex';

    try {
        const res = await fetch(`${API_BASE}/incidents/${id}`);
        const inc = await res.json();

        modalSeverity.className = `badge severity-${inc.severity.toLowerCase()}`;
        modalSeverity.textContent = inc.severity;
        modalStatus.textContent = inc.status.replace('_', ' ').toUpperCase();
        
        modalReport.textContent = inc.report || 'No detailed report generated yet.';

        if (inc.status === 'pending_approval') {
            approvalSection.style.display = 'flex';
            analystNotes.value = '';
        }
    } catch (e) {
        modalReport.textContent = 'Failed to load details.';
    }
}

closeModal.addEventListener('click', () => {
    modal.style.display = 'none';
    currentIncidentId = null;
});

// Approval Actions
approveBtn.addEventListener('click', () => handleApproval(true));
rejectBtn.addEventListener('click', () => handleApproval(false));

async function handleApproval(isApproved) {
    if (!currentIncidentId) return;

    const endpoint = isApproved ? 'approve' : 'reject';
    const notes = analystNotes.value.trim();

    try {
        const res = await fetch(`${API_BASE}/incidents/${currentIncidentId}/${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ approved: isApproved, notes })
        });
        
        if (res.ok) {
            modal.style.display = 'none';
            fetchIncidents();
        } else {
            const err = await res.json();
            alert(err.detail || 'Action failed');
        }
    } catch (e) {
        alert('Action failed: ' + e.message);
    }
}

// Utils
function setLoading(button, isLoading) {
    const text = button.querySelector('.btn-text');
    const loader = button.querySelector('.loader');
    if (isLoading) {
        text.style.display = 'none';
        loader.style.display = 'block';
        button.disabled = true;
    } else {
        text.style.display = 'block';
        loader.style.display = 'none';
        button.disabled = false;
    }
}
