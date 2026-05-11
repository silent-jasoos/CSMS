// dashboard.js
// CyberShield CSMS Dashboard Page Logic

// ===============================
// AUTH CHECK
// ===============================
if (!localStorage.getItem('csms_token')) {
    window.location.href = '/login';
}

// ===============================
// LOAD DASHBOARD STATS
// ===============================
async function loadStats() {
    try {
        const res = await fetch('/api/dashboard/stats', {
            method: 'GET',
            headers: CSMSCharts.getAuthHeaders()
        });

        if (!res.ok) {
            throw new Error(`Failed to load stats: ${res.status}`);
        }

        const data = await res.json();

        const setText = (id, value) => {
            const el = document.getElementById(id);
            if (el) el.textContent = value;
        };

        setText('totalEvents', data.todayEvents || 0);
        setText('activeThreats', data.activeThreats || 0);
        setText('blockedConnections', data.blockedConnections || 0);
        setText('honeypotCaptures', data.honeypotCaptures || 0);

        // Threat blinking effect
        const threatEl = document.getElementById('activeThreats');

        if (threatEl) {
            if (data.activeThreats > 0) {
                threatEl.classList.add('blinking');
            } else {
                threatEl.classList.remove('blinking');
            }
        }

    } catch (error) {
        console.error('Error loading dashboard stats:', error);
    }
}

// ===============================
// LOAD ACTIVITY FEED
// ===============================
async function loadActivityFeed() {
    try {
        const res = await fetch(
            '/api/logs?size=10&sort=timestamp,desc',
            {
                method: 'GET',
                headers: CSMSCharts.getAuthHeaders()
            }
        );

        if (!res.ok) {
            throw new Error(`Failed to load activity feed: ${res.status}`);
        }

        const data = await res.json();

        const activityFeed = document.getElementById('activityFeed');

        if (!activityFeed) return;

        const rows = (data.content || [])
            .map((entry) => {
                let rowClass = '';

                switch (entry.eventType) {
                    case 'LOGIN_SUCCESS':
                        rowClass = 'row-success';
                        break;

                    case 'FIREWALL_BLOCK':
                    case 'LOGIN_FAIL':
                        rowClass = 'row-danger';
                        break;

                    case 'IDS_ALERT':
                        rowClass = 'row-warning';
                        break;

                    default:
                        rowClass = '';
                }

                const formattedTime = entry.timestamp
                    ? new Date(entry.timestamp).toLocaleTimeString()
                    : 'N/A';

                return `
                    <tr class="${rowClass}">
                        <td>${formattedTime}</td>
                        <td>${entry.eventType || 'Unknown'}</td>
                        <td>${entry.sourceIp || 'N/A'}</td>
                        <td>${entry.message || 'No details available'}</td>
                    </tr>
                `;
            })
            .join('');

        activityFeed.innerHTML = rows;

    } catch (error) {
        console.error('Error loading activity feed:', error);
    }
}

// ===============================
// LOAD ALERT COUNT
// ===============================
async function loadAlertCount() {
    try {
        const res = await fetch('/api/ids/alerts/active-count', {
            method: 'GET',
            headers: CSMSCharts.getAuthHeaders()
        });

        if (!res.ok) {
            throw new Error(`Failed to load alert count: ${res.status}`);
        }

        const data = await res.json();

        const badge = document.getElementById('alertBadge');

        if (badge) {
            badge.textContent = data.count || 0;
        }

    } catch (error) {
        console.error('Error loading alert count:', error);
    }
}

// ===============================
// INITIALIZE CHARTS
// ===============================
async function initCharts() {
    try {
        const res = await fetch('/api/reports/summary', {
            method: 'GET',
            headers: CSMSCharts.getAuthHeaders()
        });

        if (!res.ok) {
            throw new Error(`Failed to load chart data: ${res.status}`);
        }

        const data = await res.json();

        const labels = CSMSCharts.generateHourLabels();

        // Attacks Line Chart
        CSMSCharts.createLineChart(
            'attacksChart',
            labels,
            data.hourlyAttacks || Array(24).fill(0),
            'Attacks'
        );

        // Threat Distribution Doughnut Chart
        CSMSCharts.createDoughnutChart(
            'threatChart',
            ['Login Fail', 'Firewall Block', 'IDS Alert', 'Honeypot'],
            [
                data.loginFails || 0,
                data.firewallBlocks || 0,
                data.idsAlerts || 0,
                data.honeypotCaptures || 0
            ],
            ['#FF4444', '#FF8C00', '#B44FFF', '#00D4FF']
        );

    } catch (error) {
        console.error('Error initializing charts:', error);
    }
}

// ===============================
// LOGOUT FUNCTIONALITY
// ===============================
const logoutBtn = document.getElementById('logoutBtn');

if (logoutBtn) {
    logoutBtn.addEventListener('click', () => {
        localStorage.removeItem('csms_token');
        window.location.href = '/login';
    });
}

// ===============================
// PAGE INITIALIZATION
// ===============================
document.addEventListener('DOMContentLoaded', async () => {

    // Initial loads
    await initCharts();
    await loadStats();
    await loadActivityFeed();
    await loadAlertCount();

    // Auto refresh intervals
    setInterval(loadStats, 3000);
    setInterval(loadActivityFeed, 3000);
    setInterval(loadAlertCount, 5000);
});