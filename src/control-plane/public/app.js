let csrf = '';

const $ = (selector) => document.querySelector(selector);
const notice = $('#notice');

function bytes(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '='));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function base64url(value) {
  const binary = String.fromCharCode(...new Uint8Array(value));
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function registrationOptions(options) {
  return {
    ...options,
    challenge: bytes(options.challenge),
    user: { ...options.user, id: bytes(options.user.id) },
    excludeCredentials: options.excludeCredentials?.map((item) => ({ ...item, id: bytes(item.id) })),
  };
}

function authenticationOptions(options) {
  return {
    ...options,
    challenge: bytes(options.challenge),
    allowCredentials: options.allowCredentials?.map((item) => ({ ...item, id: bytes(item.id) })),
  };
}

function registrationResponse(credential) {
  return {
    id: credential.id,
    rawId: base64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: base64url(credential.response.clientDataJSON),
      attestationObject: base64url(credential.response.attestationObject),
      transports: credential.response.getTransports?.() || [],
    },
  };
}

function authenticationResponse(credential) {
  return {
    id: credential.id,
    rawId: base64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: base64url(credential.response.clientDataJSON),
      authenticatorData: base64url(credential.response.authenticatorData),
      signature: base64url(credential.response.signature),
      userHandle: credential.response.userHandle ? base64url(credential.response.userHandle) : undefined,
    },
  };
}

async function api(path, options = {}) {
  const headers = { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) };
  if (csrf && options.method && options.method !== 'GET') headers['X-CSRF-Token'] = csrf;
  const response = await fetch(path, { ...options, headers });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
  return body;
}

function setNotice(message, error = false) {
  notice.textContent = message;
  notice.classList.toggle('error', error);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[character]);
}

async function restoreSession() {
  try {
    const session = await api('/api/auth/session');
    csrf = session.csrf;
    showDashboard(session.owner);
  } catch {
    showAuth();
  }
}

function showAuth() {
  csrf = '';
  $('#auth').hidden = false;
  $('#dashboard').hidden = true;
  $('#session-actions').hidden = true;
}

function showDashboard(owner) {
  $('#auth').hidden = true;
  $('#dashboard').hidden = false;
  $('#session-actions').hidden = false;
  $('#owner-name').textContent = owner.displayName;
  refreshAll();
}

async function login() {
  const start = await api('/api/auth/login/options', { method: 'POST', body: '{}' });
  const credential = await navigator.credentials.get({ publicKey: authenticationOptions(start.options) });
  const result = await api('/api/auth/login/verify', {
    method: 'POST',
    body: JSON.stringify({ ceremonyId: start.ceremonyId, response: authenticationResponse(credential) }),
  });
  csrf = result.csrf;
  showDashboard(result.owner);
  setNotice('Вход подтверждён passkey.');
}

async function register() {
  const bootstrapToken = $('#bootstrap-token').value;
  const label = $('#passkey-label').value;
  const start = await api('/api/auth/register/options', { method: 'POST', body: JSON.stringify({ bootstrapToken, label }) });
  const credential = await navigator.credentials.create({ publicKey: registrationOptions(start.options) });
  const result = await api('/api/auth/register/verify', {
    method: 'POST',
    body: JSON.stringify({ ceremonyId: start.ceremonyId, bootstrapToken, response: registrationResponse(credential) }),
  });
  $('#bootstrap-token').value = '';
  csrf = result.csrf;
  showDashboard(result.owner);
  setNotice('Passkey зарегистрирован. Bootstrap-доступ погашен.');
}

async function refreshServers() {
  const [{ servers }, { folders }] = await Promise.all([api('/api/servers'), api('/api/folders')]);
  const target = $('#servers');
  const folderOptions = (currentFolderId) => [
    `<option value="" ${currentFolderId ? '' : 'selected'}>Без папки</option>`,
    ...folders.map((folder) => `<option value="${escapeHtml(folder.id)}" ${folder.id === currentFolderId ? 'selected' : ''}>${escapeHtml(folder.name)}</option>`),
  ].join('');
  const renderServer = (server) => {
    const states = new Map((server.snapshot?.containers || []).map((container) => [container.name, container]));
    const containers = server.allowedContainers.map((name) => {
      const state = states.get(name) || { name, status: server.connected ? 'ожидание данных' : 'агент отключён' };
      return `<article class="container-row">
        <div><strong>${escapeHtml(name)}</strong><span class="state ${state.running ? 'running' : ''}">${escapeHtml(state.status)}${state.health ? ` · ${escapeHtml(state.health)}` : ''}</span></div>
        <div class="actions">
          <button class="quiet" data-logs data-server="${escapeHtml(server.id)}" data-container="${escapeHtml(name)}" ${server.connected ? '' : 'disabled'}>Логи</button>
          ${Object.entries({ start: 'Запустить', stop: 'Остановить', restart: 'Перезапустить' }).map(([action, label]) => `<button data-action="${action}" data-server="${escapeHtml(server.id)}" data-container="${escapeHtml(name)}" ${server.connected ? '' : 'disabled'}>${label}</button>`).join('')}
        </div>
      </article>`;
    }).join('');
    return `<section class="server-card">
      <div class="server-title">
        <div><h3>${escapeHtml(server.displayName)}</h3><code>${escapeHtml(server.id)}</code></div>
        <div class="server-meta">
          <label class="folder-picker">Папка
            <select data-server-folder data-server="${escapeHtml(server.id)}" ${server.revokedAt ? 'disabled' : ''}>${folderOptions(server.folderId)}</select>
          </label>
          <span class="connection ${server.connected ? 'online' : ''}">${server.connected ? 'online' : 'offline'}</span>
        </div>
      </div>${containers}
    </section>`;
  };
  const renderFolder = (folder, folderServers, ungrouped = false) => `<section class="folder-card">
    <div class="folder-title">
      <div><span class="folder-icon" aria-hidden="true">◆</span><h3>${escapeHtml(folder.name)}</h3><span class="folder-count">${folderServers.length}</span></div>
      ${ungrouped ? '' : `<div class="actions"><button class="quiet compact" data-rename-folder="${escapeHtml(folder.id)}" data-folder-name="${escapeHtml(folder.name)}">Переименовать</button><button class="quiet compact danger" data-delete-folder="${escapeHtml(folder.id)}" data-folder-name="${escapeHtml(folder.name)}">Удалить</button></div>`}
    </div>
    <div class="servers">${folderServers.map(renderServer).join('') || '<div class="empty">В этой папке пока нет агентов.</div>'}</div>
  </section>`;

  if (servers.length === 0 && folders.length === 0) {
    target.innerHTML = '<div class="empty">Нет зарегистрированных серверов. Создайте папки заранее или дождитесь первого агента.</div>';
    return;
  }
  const byFolder = new Map(folders.map((folder) => [folder.id, []]));
  const ungrouped = [];
  for (const server of servers) {
    const destination = server.folderId && byFolder.get(server.folderId);
    (destination || ungrouped).push(server);
  }
  target.innerHTML = [
    ...folders.map((folder) => renderFolder(folder, byFolder.get(folder.id))),
    renderFolder({ id: '', name: 'Без папки' }, ungrouped, true),
  ].join('');
}

async function createFolder(event) {
  event.preventDefault();
  const input = $('#folder-name');
  const name = input.value.trim();
  if (!name) return;
  await api('/api/folders', { method: 'POST', body: JSON.stringify({ name }) });
  input.value = '';
  setNotice(`Папка «${name}» создана.`);
  await refreshServers();
}

async function renameFolder(button) {
  const name = window.prompt('Новое название папки', button.dataset.folderName)?.trim();
  if (!name || name === button.dataset.folderName) return;
  await api(`/api/folders/${encodeURIComponent(button.dataset.renameFolder)}`, { method: 'PATCH', body: JSON.stringify({ name }) });
  setNotice(`Папка переименована в «${name}».`);
  await refreshServers();
}

async function deleteFolder(button) {
  if (!window.confirm(`Удалить папку «${button.dataset.folderName}»? Агенты перейдут в раздел «Без папки».`)) return;
  const result = await api(`/api/folders/${encodeURIComponent(button.dataset.deleteFolder)}`, { method: 'DELETE', body: '{}' });
  setNotice(`Папка удалена. Перемещено агентов: ${result.movedAgents}.`);
  await refreshServers();
}

async function moveServer(select) {
  const folderId = select.value || null;
  await api(`/api/servers/${encodeURIComponent(select.dataset.server)}/folder`, { method: 'PATCH', body: JSON.stringify({ folderId }) });
  setNotice('Агент перемещён в выбранную папку.');
  await refreshServers();
}

async function refreshEnrollmentRequests() {
  const { requests } = await api('/api/enrollment-requests');
  const target = $('#enrollment-requests');
  if (requests.length === 0) {
    target.innerHTML = '<div class="empty">Новых серверов, ожидающих подтверждения, нет.</div>';
    return;
  }
  target.innerHTML = requests.map((request) => `<article class="server-card">
    <div class="server-title">
      <div><h3>${escapeHtml(request.displayName)}</h3><code>${escapeHtml(request.id)}</code></div>
      <span class="connection">ожидает подтверждения</span>
    </div>
    <p>Контейнеры: <strong>${request.allowedContainers.map(escapeHtml).join(', ')}</strong></p>
    <p><small>Первый запрос: ${escapeHtml(new Date(request.requestedAt).toLocaleString())} · ключ: ${escapeHtml(request.publicKeyFingerprint)}…</small></p>
    <div class="actions"><button data-approve-agent="${escapeHtml(request.id)}">Подтвердить сервер</button></div>
  </article>`).join('');
}

async function approveAgent(button) {
  const serverId = button.dataset.approveAgent;
  if (!window.confirm(`Разрешить серверу ${serverId} управлять только указанными контейнерами?`)) return;
  await api(`/api/enrollment-requests/${encodeURIComponent(serverId)}/approve`, { method: 'POST', body: '{}' });
  setNotice(`Сервер ${serverId} подтверждён. Агент подключится автоматически.`);
  await refreshAll();
}

async function prepareAction(button) {
  const operation = { serverId: button.dataset.server, container: button.dataset.container, action: button.dataset.action };
  const prepared = await api('/api/actions/prepare', { method: 'POST', body: JSON.stringify(operation) });
  $('#confirm-summary').textContent = prepared.summary;
  const dialog = $('#confirm-dialog');
  dialog.showModal();
  const answer = await new Promise((resolve) => dialog.addEventListener('close', () => resolve(dialog.returnValue), { once: true }));
  if (answer !== 'confirm') return setNotice('Действие отменено.');
  const result = await api('/api/actions/execute', { method: 'POST', body: JSON.stringify({ confirmationId: prepared.confirmationId }) });
  setNotice(`Команда выполнена: ${result.outcome}.`);
  await refreshAll();
}

async function showLogs(button) {
  const server = encodeURIComponent(button.dataset.server);
  const container = encodeURIComponent(button.dataset.container);
  const result = await api(`/api/servers/${server}/containers/${container}/logs?tail=300`);
  $('#logs-title').textContent = `Логи: ${result.container}`;
  $('#logs-content').textContent = result.logs || '(пусто)';
  $('#logs-dialog').showModal();
}

async function refreshAudit() {
  const { entries } = await api('/api/audit?limit=50');
  $('#audit').innerHTML = entries.map((entry) => `<div class="audit-row"><time>${escapeHtml(new Date(entry.timestamp).toLocaleString())}</time><strong>${escapeHtml(entry.event)}</strong><span>${escapeHtml(entry.target || '')}</span><em>${escapeHtml(entry.outcome)}</em></div>`).join('') || '<div class="empty">Журнал пока пуст.</div>';
}

async function refreshAll() {
  await Promise.all([refreshEnrollmentRequests(), refreshServers(), refreshAudit()]);
}

async function run(task) {
  try { await task(); } catch (error) { setNotice(error.message, true); }
}

$('#login').addEventListener('click', () => run(login));
$('#register').addEventListener('click', () => run(register));
$('#refresh').addEventListener('click', () => run(refreshServers));
$('#refresh-enrollment-requests').addEventListener('click', () => run(refreshEnrollmentRequests));
$('#refresh-audit').addEventListener('click', () => run(refreshAudit));
$('#create-folder-form').addEventListener('submit', (event) => run(() => createFolder(event)));
$('#logout').addEventListener('click', () => run(async () => {
  await api('/api/auth/logout', { method: 'POST', body: '{}' });
  showAuth();
  setNotice('Сессия завершена.');
}));
$('#servers').addEventListener('click', (event) => {
  const actionButton = event.target.closest('[data-action]');
  const logsButton = event.target.closest('[data-logs]');
  if (actionButton) run(() => prepareAction(actionButton));
  if (logsButton) run(() => showLogs(logsButton));
  const renameButton = event.target.closest('[data-rename-folder]');
  const deleteButton = event.target.closest('[data-delete-folder]');
  if (renameButton) run(() => renameFolder(renameButton));
  if (deleteButton) run(() => deleteFolder(deleteButton));
});
$('#servers').addEventListener('change', (event) => {
  const select = event.target.closest('[data-server-folder]');
  if (select) run(() => moveServer(select));
});
$('#enrollment-requests').addEventListener('click', (event) => {
  const button = event.target.closest('[data-approve-agent]');
  if (button) run(() => approveAgent(button));
});

restoreSession();
