// firewall.js
// Firewall management page logic

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

async function loadRules() {
    try {
        const res = await fetch('/api/firewall/rules', {
            method: 'GET',
            headers: getAuthHeaders()
        });

        if (!res.ok) {
            throw new Error(`Failed to load rules: ${res.status}`);
        }

        const rules = await res.json();
        const tableBody = document.getElementById('rulesTableBody');

        if (!tableBody) {
            return;
        }

        const rows = (rules || []).map((rule) => {
            const ruleJson = JSON.stringify(rule)
                .replace(/\\/g, '\\\\')
                .replace(/"/g, "'")
                .replace(/'/g, "\\'");

            return `
                <tr>
                    <td>${rule.ruleName || ''}</td>
                    <td>${rule.ipAddress || ''}</td>
                    <td>${rule.portNumber || 'Any'}</td>
                    <td>${rule.protocol || ''}</td>
                    <td><span class="badge ${rule.action ? rule.action.toLowerCase() : ''}">${rule.action || ''}</span></td>
                    <td>${rule.priority != null ? rule.priority : ''}</td>
                    <td>
                        <input type="checkbox" ${rule.isActive ? 'checked' : ''} onchange="toggleRule(${rule.id}, ${rule.isActive})">
                    </td>
                    <td>
                        <button onclick="openEditModal(${ruleJson})">Edit</button>
                        <button onclick="deleteRule(${rule.id})">Delete</button>
                    </td>
                </tr>
            `;
        }).join('');

        tableBody.innerHTML = rows;
    } catch (error) {
        console.error('Error loading firewall rules:', error);
        alert('Error loading firewall rules: ' + error.message);
    }
}

function openAddModal() {
    document.getElementById('ruleId').value = '';
    document.getElementById('ruleName').value = '';
    document.getElementById('ipAddress').value = '';
    document.getElementById('portNumber').value = '';
    document.getElementById('protocol').value = 'TCP';
    document.getElementById('action').value = 'ALLOW';
    document.getElementById('priority').value = '1';
    document.getElementById('ruleActive').checked = true;
    document.getElementById('modalHeading').textContent = 'Add New Rule';
    document.getElementById('ruleModal').style.display = 'block';
}

function openEditModal(rule) {
    document.getElementById('ruleId').value = rule.id || '';
    document.getElementById('ruleName').value = rule.ruleName || '';
    document.getElementById('ipAddress').value = rule.ipAddress || '';
    document.getElementById('portNumber').value = rule.portNumber != null ? rule.portNumber : '';
    document.getElementById('protocol').value = rule.protocol || 'TCP';
    document.getElementById('action').value = rule.action || 'ALLOW';
    document.getElementById('priority').value = rule.priority != null ? rule.priority : '1';
    document.getElementById('ruleActive').checked = Boolean(rule.isActive);
    document.getElementById('modalHeading').textContent = 'Edit Rule';
    document.getElementById('ruleModal').style.display = 'block';
}

function closeModal() {
    const modal = document.getElementById('ruleModal');
    if (modal) {
        modal.style.display = 'none';
    }
}

async function saveRule() {
    try {
        const id = document.getElementById('ruleId').value;
        const ruleName = document.getElementById('ruleName').value.trim();
        const ipAddress = document.getElementById('ipAddress').value.trim();
        const portNumberValue = document.getElementById('portNumber').value.trim();
        const protocol = document.getElementById('protocol').value;
        const action = document.getElementById('action').value;
        const priorityValue = document.getElementById('priority').value.trim();
        const isActive = document.getElementById('ruleActive').checked;

        const payload = {
            ruleName,
            ipAddress,
            protocol,
            action,
            priority: parseInt(priorityValue, 10) || 0,
            isActive
        };

        if (portNumberValue !== '') {
            payload.portNumber = parseInt(portNumberValue, 10);
        }

        const method = id ? 'PUT' : 'POST';
        const url = id ? `/api/firewall/rules/${id}` : '/api/firewall/rules';

        const res = await fetch(url, {
            method,
            headers: getAuthHeaders(),
            body: JSON.stringify(payload)
        });

        if (!res.ok) {
            throw new Error(`Failed to save rule: ${res.status}`);
        }

        closeModal();
        await loadRules();
    } catch (error) {
        console.error('Error saving rule:', error);
        alert('Error saving rule: ' + error.message);
    }
}

async function deleteRule(id) {
    try {
        if (!confirm('Delete rule #' + id + '?')) {
            return;
        }

        const res = await fetch(`/api/firewall/rules/${id}`, {
            method: 'DELETE',
            headers: getAuthHeaders()
        });

        if (!res.ok) {
            throw new Error(`Failed to delete rule: ${res.status}`);
        }

        await loadRules();
    } catch (error) {
        console.error('Error deleting rule:', error);
        alert('Error deleting rule: ' + error.message);
    }
}

async function toggleRule(id, currentState) {
    try {
        const res = await fetch(`/api/firewall/rules/${id}`, {
            method: 'PUT',
            headers: getAuthHeaders(),
            body: JSON.stringify({ isActive: !currentState })
        });

        if (!res.ok) {
            throw new Error(`Failed to toggle rule: ${res.status}`);
        }

        await loadRules();
    } catch (error) {
        console.error('Error toggling rule:', error);
        alert('Error toggling rule: ' + error.message);
    }
}

async function simulateTraffic() {
    try {
        const ip = document.getElementById('simIP').value.trim();
        const port = document.getElementById('simPort').value.trim();
        const protocol = document.getElementById('simProtocol').value;

        if (!ip || !port) {
            alert('Please enter IP and Port');
            return;
        }

        const res = await fetch('/api/firewall/simulate', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({
                ipAddress: ip,
                portNumber: parseInt(port, 10),
                protocol
            })
        });

        if (!res.ok) {
            throw new Error(`Failed to simulate traffic: ${res.status}`);
        }

        const data = await res.json();
        const resultDiv = document.getElementById('simResult');

        if (!resultDiv) {
            return;
        }

        resultDiv.classList.remove('result-allow', 'result-block', 'slide-in');

        if (data.result === 'ALLOW') {
            resultDiv.innerHTML = `<div class="result-allow">TRAFFIC ALLOWED<br>Policy: ${data.matchedRule || 'None'}</div>`;
        } else {
            resultDiv.innerHTML = `<div class="result-block">TRAFFIC BLOCKED<br>Rule: ${data.matchedRule || 'None'}</div>`;
        }

        resultDiv.style.display = 'block';
        void resultDiv.offsetWidth;
        resultDiv.classList.add('slide-in');
    } catch (error) {
        console.error('Error simulating traffic:', error);
        alert('Error simulating traffic: ' + error.message);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    loadRules();
});
