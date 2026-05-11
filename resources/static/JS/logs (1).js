// logs.js
// System logs page logic

let currentPage = 0;
let autoRefreshInterval = null;
let totalPages = 0;

function getAuthHeaders() {
    const token = localStorage.getItem('csms_token');
    const headers = {
        'Content-Type': 'application/json'
    };

    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    return headers;
}

function buildFilterParams() {
    const eventType = document.getElementById('eventTypeFilter')?.value || '';
    const severity = document.getElementById('severityFilter')?.value || '';
    const sourceIP = document.getElementById('sourceIPFilter')?.value || '';
    const username = document.getElementById('usernameFilter')?.value || '';

    return new URLSearchParams({
        eventType,
        severity,
        sourceIP,
        username,
        page: currentPage,
        size: 20,
        sort: 'timestamp,desc'
    });
}

async function loadLogs() {
    try {
        const params = buildFilterParams();
        const res = await fetch(`/api/logs?${params.toString()}`, {
            method: 'GET',
            headers: getAuthHeaders()
        });

        if (!res.ok) {
            throw new Error(`Failed to load logs: ${res.status}`);
        }

        const data = await res.json();
        totalPages = data.totalPages || 0;

        const rows = (data.content || []).map((entry) => {
            let rowClass = '';

            switch (entry.eventType) {
                case 'LOGIN_SUCCESS':
                    rowClass = 'row-success';
                    break;
                case 'LOGIN_FAIL':
                case 'FIREWALL_BLOCK':
                    rowClass = 'row-danger';
                    break;
                case 'IDS_ALERT':
                    rowClass = 'row-warning';
                    break;
                default:
                    rowClass = '';
            }

            const severityClass = entry.severity ? `sev${entry.severity.toLowerCase()}` : '';

            return `
                <tr class="${rowClass}">
                    <td>${entry.timestamp || ''}</td>
                    <td>${entry.eventType || ''}</td>
                    <td><span class="badge ${severityClass}">${entry.severity || ''}</span></td>
                    <td>${entry.sourceIP || ''}</td>
                    <td>${entry.username || ''}</td>
                    <td>${entry.message || ''}</td>
                </tr>
            `;
        }).join('');

        const tableBody = document.getElementById('logsTableBody');
        if (tableBody) {
            tableBody.innerHTML = rows;
        }

        const logCount = document.getElementById('logCount');
        if (logCount) {
            logCount.textContent = `Showing ${data.content?.length || 0} of ${data.totalElements || 0} entries`;
        }

        renderPagination(data.number || 0, totalPages);
    } catch (error) {
        console.error('Error loading logs:', error);
        alert('Error loading logs: ' + error.message);
    }
}

function renderPagination(currentPageIndex, totalPageCount) {
    const pagination = document.getElementById('pagination');
    if (!pagination) {
        return;
    }

    const maxButtons = Math.min(totalPageCount, 7);
    let pagesHtml = '';

    pagesHtml += `<button ${currentPageIndex === 0 ? 'disabled' : ''} onclick="goToPage(${Math.max(0, currentPageIndex - 1)})">Previous</button>`;

    for (let i = 0; i < maxButtons; i += 1) {
        pagesHtml += `<button ${i === currentPageIndex ? 'class="active"' : ''} onclick="goToPage(${i})">${i + 1}</button>`;
    }

    pagesHtml += `<button ${currentPageIndex === totalPageCount - 1 || totalPageCount === 0 ? 'disabled' : ''} onclick="goToPage(${Math.min(totalPageCount - 1, currentPageIndex + 1)})">Next</button>`;

    pagination.innerHTML = pagesHtml;
}

function goToPage(page) {
    currentPage = page;
    loadLogs();
}

function applyFilters() {
    currentPage = 0;
    loadLogs();
}

function resetFilters() {
    const eventTypeFilter = document.getElementById('eventTypeFilter');
    const severityFilter = document.getElementById('severityFilter');
    const sourceIPFilter = document.getElementById('sourceIPFilter');
    const usernameFilter = document.getElementById('usernameFilter');

    if (eventTypeFilter) eventTypeFilter.value = '';
    if (severityFilter) severityFilter.value = '';
    if (sourceIPFilter) sourceIPFilter.value = '';
    if (usernameFilter) usernameFilter.value = '';

    currentPage = 0;
    loadLogs();
}

function toggleAutoRefresh() {
    const btn = document.getElementById('autoRefreshBtn');

    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
        if (btn) {
            btn.textContent = 'Auto Refresh: OFF';
            btn.classList.remove('active');
        }
    } else {
        autoRefreshInterval = setInterval(loadLogs, 5000);
        if (btn) {
            btn.textContent = 'Auto Refresh: ON';
            btn.classList.add('active');
        }
    }
}

async function exportCSV() {
    try {
        const params = buildFilterParams();
        params.set('export', 'csv');

        const headers = typeof CSMSCharts !== 'undefined' && CSMSCharts.getAuthHeaders ? CSMSCharts.getAuthHeaders() : getAuthHeaders();
        const res = await fetch(`/api/logs/export?${params.toString()}`, {
            method: 'GET',
            headers
        });

        if (!res.ok) {
            throw new Error(`Failed to export CSV: ${res.status}`);
        }

        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `cybershield_logs_${new Date().toISOString().split('T')[0]}.csv`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
    } catch (error) {
        console.error('Error exporting CSV:', error);
        alert('Error exporting CSV: ' + error.message);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    loadLogs();

    const applyFiltersBtn = document.getElementById('applyFilters');
    const resetFiltersBtn = document.getElementById('resetFilters');
    const autoRefreshBtn = document.getElementById('autoRefreshBtn');
    const exportBtn = document.getElementById('exportBtn');

    if (applyFiltersBtn) {
        applyFiltersBtn.addEventListener('click', applyFilters);
    }
    if (resetFiltersBtn) {
        resetFiltersBtn.addEventListener('click', resetFilters);
    }
    if (autoRefreshBtn) {
        autoRefreshBtn.addEventListener('click', toggleAutoRefresh);
    }
    if (exportBtn) {
        exportBtn.addEventListener('click', exportCSV);
    }
});
