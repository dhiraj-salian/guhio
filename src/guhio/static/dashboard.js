async function api(path, options = {}) {
    const res = await fetch(path, {
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        ...options,
    });
    const data = res.status !== 204 ? await res.json().catch(() => ({})) : {};
    if (!res.ok) {
        throw new Error(data.error || `HTTP ${res.status}`);
    }
    return data;
}

function showMessage(text, isError) {
    const el = document.getElementById('message');
    el.textContent = text;
    el.className = 'message ' + (isError ? 'error' : 'success');
    setTimeout(() => el.className = 'message', 4000);
}

async function refreshStatus() {
    const status = await api('/api/status');
    document.getElementById('unlock-section').style.display = status.unlocked ? 'none' : 'block';
    document.getElementById('vault-section').style.display = status.unlocked ? 'block' : 'none';
    if (status.unlocked) await loadCredentials();
}

async function unlock() {
    const password = document.getElementById('master-password').value;
    try {
        await api('/api/unlock', { method: 'POST', body: JSON.stringify({ password }) });
        document.getElementById('master-password').value = '';
        await refreshStatus();
    } catch (err) {
        showMessage(err.message, true);
    }
}

async function lock() {
    try {
        await api('/api/lock', { method: 'POST' });
        await refreshStatus();
    } catch (err) {
        showMessage(err.message, true);
    }
}

function createRemoveButton(name) {
    const btn = document.createElement('button');
    btn.className = 'btn btn-danger btn-sm';
    btn.textContent = 'Remove';
    btn.setAttribute('aria-label', `Remove credential ${name}`);
    btn.addEventListener('click', () => removeCredential(name));
    return btn;
}

async function loadCredentials() {
    try {
        const credentials = await api('/api/credentials');
        const tbody = document.querySelector('#credentials-table tbody');
        const list = document.getElementById('credentials-list');
        tbody.innerHTML = '';
        list.innerHTML = '';

        if (credentials.length === 0) {
            document.getElementById('empty-state').style.display = 'block';
            document.getElementById('credentials-table').style.display = 'none';
            document.getElementById('credentials-list').style.display = 'none';
        } else {
            document.getElementById('empty-state').style.display = 'none';

            for (const cred of credentials) {
                const createdText = new Date(cred.created_at).toLocaleString();

                const tr = document.createElement('tr');

                const tdName = document.createElement('td');
                tdName.textContent = cred.name;
                tr.appendChild(tdName);

                const tdCreated = document.createElement('td');
                tdCreated.textContent = createdText;
                tr.appendChild(tdCreated);

                const tdAction = document.createElement('td');
                tdAction.appendChild(createRemoveButton(cred.name));
                tr.appendChild(tdAction);

                tbody.appendChild(tr);

                const li = document.createElement('li');
                li.className = 'credential-card';

                const nameDiv = document.createElement('div');
                nameDiv.className = 'credential-name';
                nameDiv.textContent = cred.name;
                li.appendChild(nameDiv);

                const metaDiv = document.createElement('div');
                metaDiv.className = 'credential-meta';
                metaDiv.textContent = createdText;
                li.appendChild(metaDiv);

                const actionDiv = document.createElement('div');
                actionDiv.appendChild(createRemoveButton(cred.name));
                li.appendChild(actionDiv);

                list.appendChild(li);
            }

            const isDesktop = window.matchMedia('(min-width: 640px)').matches;
            document.getElementById('credentials-table').style.display = isDesktop ? 'table' : 'none';
            document.getElementById('credentials-list').style.display = isDesktop ? 'none' : 'block';
        }
    } catch (err) {
        showMessage(err.message, true);
    }
}

function handleResize() {
    const hasCredentials = document.querySelector('#credentials-table tbody').children.length > 0;
    if (!hasCredentials) return;
    const isDesktop = window.matchMedia('(min-width: 640px)').matches;
    document.getElementById('credentials-table').style.display = isDesktop ? 'table' : 'none';
    document.getElementById('credentials-list').style.display = isDesktop ? 'none' : 'block';
}

async function addCredential() {
    const name = document.getElementById('credential-name').value.trim();
    const value = document.getElementById('credential-value').value;
    if (!name || !value) {
        showMessage('Name and value are required', true);
        return;
    }
    try {
        await api('/api/credentials', { method: 'POST', body: JSON.stringify({ name, value }) });
        document.getElementById('credential-name').value = '';
        document.getElementById('credential-value').value = '';
        await loadCredentials();
        showMessage('Credential saved', false);
    } catch (err) {
        showMessage(err.message, true);
    }
}

async function removeCredential(name) {
    if (!confirm(`Remove credential "${name}"?`)) return;
    try {
        await api(`/api/credentials/${encodeURIComponent(name)}`, { method: 'DELETE' });
        await loadCredentials();
        showMessage('Credential deleted', false);
    } catch (err) {
        showMessage(err.message, true);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('unlock-btn').addEventListener('click', unlock);
    document.getElementById('lock-btn').addEventListener('click', lock);
    document.getElementById('add-credential-btn').addEventListener('click', addCredential);
    window.addEventListener('resize', handleResize);
    refreshStatus();
});
