// ids.js
// IDS alerts page logic

const seenAlertIds = new Set();

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

function formatTime(isoString) {
    return new Date(isoString).toLocaleString();
}

function updateAlertCard(alert) {
    const card = document.getElementById(`alert-${alert.id}`);
    if (!card) {
        return;
    }

    const badge = card.querySelector('.alert-badge');
    const title = card.querySelector('.alert-body h4');
    const description = card.querySelector('.alert-body p');
    const meta = card.querySelector('.alert-body small');
    const button = card.querySelector('button');

    if (badge) {
        const severityClass = {
            LOW: 'sev-low',
            MEDIUM: 'sev-medium',
            HIGH: 'sev-high',
            CRITICAL: 'sev-critical'
        }[alert.severity] || '';

        badge.className = `alert-badge ${severityClass}`;
        badge.textContent = alert.severity;
    }

    if (title) {
        title.textContent = alert.alertType;
    }

    if (description) {
        description.textContent = alert.description;
    }

    if (meta) {
        meta.textContent = `Source: ${alert.sourceIP} | ${formatTime(alert.detectedAt)}`;
    }

    if (button) {
        button.textContent = alert.isResolved ? 'Resolved' : 'Resolve';
        button.disabled = !!alert.isResolved;
    }

    if (alert.isResolved) {
        card.classList.add('resolved');
    } else {
        card.classList.remove('resolved');
    }
}

async function loadAlerts() {
    try {
        const severity = document.getElementById('severityFilter')?.value || 'ALL';
        const status = document.getElementById('statusFilter')?.value || '';
        const query = new URLSearchParams({
            severity: severity !== 'ALL' ? severity : '',
            resolved: status
        }).toString();
        const url = `/api/ids/alerts?${query}`;

        const res = await fetch(url, {
            method: 'GET',
            headers: getAuthHeaders()
        });

        if (!res.ok) {
            throw new Error(`Failed to load alerts: ${res.status}`);
        }

        const data = await res.json();
        const alerts = data.content || [];
        const alertFeed = document.getElementById('alertFeed');

        if (!alertFeed) {
            return;
        }

        alerts.forEach((alert) => {
            const alertId = alert.id;
            const existingCard = document.getElementById(`alert-${alertId}`);

            if (seenAlertIds.has(alertId) && existingCard) {
                updateAlertCard(alert);
                return;
            }

            const severityClass = {
                LOW: 'sev-low',
                MEDIUM: 'sev-medium',
                HIGH: 'sev-high',
                CRITICAL: 'sev-critical'
            }[alert.severity] || '';

            const cardHtml = document.createElement('div');
            cardHtml.className = 'alert-card slide-in';
            cardHtml.id = `alert-${alertId}`;
            cardHtml.innerHTML = `
                <div class="alert-badge ${severityClass}">${alert.severity}</div>
                <div class="alert-body">
                    <h4>${alert.alertType}</h4>
                    <p>${alert.description}</p>
                    <small>Source: ${alert.sourceIP} | ${formatTime(alert.detectedAt)}</small>
                </div>
                <button onclick="resolveAlert(${alertId})" ${alert.isResolved ? 'disabled' : ''}>
                    ${alert.isResolved ? 'Resolved' : 'Resolve'}
                </button>
            `;

            alertFeed.prepend(cardHtml);
            seenAlertIds.add(alertId);
        });

        updateThreatMeter(alerts);
    } catch (error) {
        console.error('Error loading alerts:', error);
        alert('Error loading alerts: ' + error.message);
    }
}

function updateThreatMeter(alerts) {
    const criticalCount = alerts.filter((alert) => alert.severity === 'CRITICAL').length;
    const highCount = alerts.filter((alert) => alert.severity === 'HIGH').length;
    const percent = Math.min(100, criticalCount * 25 + highCount * 10);
    const dashOffset = 283 - (283 * percent) / 100;

    const meter = document.getElementById('threatMeterCircle');
    const percentLabel = document.getElementById('threatPercent');

    if (meter) {
        meter.style.strokeDashoffset = dashOffset;

        if (percent < 30) {
            meter.style.stroke = '#10b981';
        } else if (percent < 60) {
            meter.style.stroke = '#fbbf24';
        } else if (percent < 80) {
            meter.style.stroke = '#f97316';
        } else {
            meter.style.stroke = '#ef4444';
        }
    }

    if (percentLabel) {
        percentLabel.textContent = `${percent}%`;
    }
}

async function resolveAlert(alertId) {
    try {
        const res = await fetch(`/api/ids/alerts/${alertId}/resolve`, {
            method: 'PUT',
            headers: getAuthHeaders()
        });

        if (!res.ok) {
            throw new Error(`Failed to resolve alert: ${res.status}`);
        }

        const card = document.getElementById(`alert-${alertId}`);
        if (card) {
            card.classList.add('resolved');
            const button = card.querySelector('button');
            if (button) {
                button.textContent = 'Resolved';
                button.disabled = true;
            }
        }
    } catch (error) {
        console.error('Error resolving alert:', error);
        alert('Error resolving alert: ' + error.message);
    }
}

function showToast(message) {
    const toast = document.createElement('div');
    toast.textContent = message;
    toast.style.position = 'fixed';
    toast.style.bottom = '24px';
    toast.style.right = '24px';
    toast.style.padding = '12px 16px';
    toast.style.background = 'rgba(17, 24, 39, 0.95)';
    toast.style.color = '#fff';
    toast.style.borderRadius = '12px';
    toast.style.boxShadow = '0 10px 30px rgba(15, 23, 42, 0.3)';
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s ease';
    toast.style.zIndex = '9999';

    document.body.appendChild(toast);
    requestAnimationFrame(() => {
        toast.style.opacity = '1';
    });

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.addEventListener('transitionend', () => {
            toast.remove();
        }, { once: true });
    }, 3000);
}

async function simulateAttack() {
    try {
        const type = document.getElementById('simAttackType')?.value || '';
        const ip = document.getElementById('simSourceIP')?.value || '10.0.0.99';

        const res = await fetch('/api/ids/simulate', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ attackType: type, sourceIP: ip })
        });

        if (!res.ok) {
            throw new Error(`Failed to simulate attack: ${res.status}`);
        }

        showToast('Simulation launched! Watch for new alert...');
    } catch (error) {
        console.error('Error simulating attack:', error);
        alert('Error simulating attack: ' + error.message);
    }
}

function applyFilters() {
    loadAlerts();
}

document.addEventListener('DOMContentLoaded', () => {
    loadAlerts();
    setInterval(loadAlerts, 3000);
});
