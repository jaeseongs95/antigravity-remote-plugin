const badgeEl = document.getElementById('connection-badge');
const refreshBtn = document.getElementById('refresh-btn');
const retryBtn = document.getElementById('retry-btn');
const errorBanner = document.getElementById('error-banner');
const errorMessageEl = document.getElementById('error-message');

const telemetrySummaryEl = document.getElementById('telemetry-summary');
const telemetryDetailEl = document.getElementById('telemetry-detail');
const progressBarEl = document.getElementById('usage-progressbar');
const progressFillEl = document.getElementById('usage-fill');
const compactBtn = document.getElementById('compact-btn');
const actionFeedbackEl = document.getElementById('action-feedback');

const pluginsListEl = document.getElementById('plugins-list');
const sidecarsListEl = document.getElementById('sidecars-list');
const diagnosticsListEl = document.getElementById('diagnostics-list');

const tabButtons = [...document.querySelectorAll('.tab-btn')];
const tabPanels = {
  statusbar: document.getElementById('panel-statusbar'),
  plugins: document.getElementById('panel-plugins'),
  diagnostics: document.getElementById('panel-diagnostics'),
};

let activeWorkspaces = [];
let activeAbortController = null;
let isCompacting = false;

function sidecarFetch(path, options = {}) {
  if (window.sidecar && typeof window.sidecar.fetch === 'function') {
    return window.sidecar.fetch(path, options);
  }
  return fetch(path, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });
}

async function postJson(path, body, signal) {
  const res = await sidecarFetch(path, {
    method: 'POST',
    body: JSON.stringify(body || {}),
    signal,
  });
  const text = await res.text();
  let parsed = null;
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch (_err) {
    parsed = { error: text || `HTTP ${res.status}` };
  }
  if (!res.ok) {
    const err = new Error(parsed?.error || `요청 실패 (HTTP ${res.status})`);
    err.status = res.status;
    err.code = parsed?.code || '';
    throw err;
  }
  return parsed;
}

function setBadge(state, label) {
  badgeEl.dataset.state = state;
  badgeEl.textContent = label;
}

function showError(message) {
  errorMessageEl.textContent = message;
  errorBanner.hidden = false;
  setBadge('error', '오류');
}

function clearError() {
  errorBanner.hidden = true;
  errorMessageEl.textContent = '';
}

function clearChildren(el) {
  while (el.firstChild) {
    el.removeChild(el.firstChild);
  }
}

function renderList(listEl, items, emptyText, formatter) {
  clearChildren(listEl);
  if (!Array.isArray(items) || items.length === 0) {
    const emptyLi = document.createElement('li');
    emptyLi.className = 'helper-text';
    emptyLi.textContent = emptyText;
    listEl.appendChild(emptyLi);
    return;
  }
  for (const item of items) {
    const row = document.createElement('li');
    row.className = 'item-row';
    const nameSpan = document.createElement('span');
    nameSpan.className = 'item-name';
    const metaSpan = document.createElement('span');
    metaSpan.className = 'item-meta';
    const { title, meta } = formatter(item);
    nameSpan.textContent = title;
    metaSpan.textContent = meta;
    row.appendChild(nameSpan);
    row.appendChild(metaSpan);
    listEl.appendChild(row);
  }
}

function renderDiagnostics(mcpSummary, state) {
  clearChildren(diagnosticsListEl);
  const entries = [
    ['버전', state?.version || '-'],
    ['연결된 브리지', Array.isArray(state?.mountedBridgeIds) ? state.mountedBridgeIds.join(', ') || '없음' : '-'],
    ['MCP 슬롯', mcpSummary?.slotMounted ? '마운트됨 (읽기 전용)' : '비활성'],
    ['원격 stdio 정책', mcpSummary?.remoteStdioPolicy || 'explicit-confirmation-required'],
    ['보호 설정 가드', mcpSummary?.protectedConfigGuard === 'enabled' ? '활성' : '비활성'],
    ['토큰·비밀 마스킹', mcpSummary?.secretsRedacted ? '적용됨' : '미확인'],
    ['활성 워크스페이스 수', String(activeWorkspaces.length)],
  ];
  for (const [label, value] of entries) {
    const row = document.createElement('div');
    row.className = 'kv-row';
    const dt = document.createElement('dt');
    dt.textContent = label;
    const dd = document.createElement('dd');
    dd.textContent = value;
    row.appendChild(dt);
    row.appendChild(dd);
    diagnosticsListEl.appendChild(row);
  }
}

function renderTelemetry(telemetryResp, statusbarAvailable) {
  if (!statusbarAvailable) {
    telemetrySummaryEl.textContent = '상태바 사이드카 비활성';
    telemetryDetailEl.textContent = 'antigravity-statusbar 플러그인이 활성화되면 토큰 사용량과 컨텍스트 정리를 사용할 수 있습니다.';
    progressFillEl.style.width = '0%';
    progressBarEl.setAttribute('aria-valuenow', '0');
    compactBtn.disabled = true;
    return;
  }

  const data = telemetryResp?.data || {};
  const used = Number(data.usedTokens ?? 0);
  const max = Number(data.maxTokenLimit ?? 0);
  const pct = max > 0 ? Math.min(100, Math.round((used / max) * 100)) : 0;

  telemetrySummaryEl.textContent = max > 0
    ? `${used.toLocaleString()} / ${max.toLocaleString()} 토큰 (${pct}%)`
    : `${used.toLocaleString()} 토큰 사용 중`;
  telemetryDetailEl.textContent = '실시간 사이드카 텔레메트리 기준';
  progressFillEl.style.width = `${pct}%`;
  progressBarEl.setAttribute('aria-valuenow', String(pct));
  compactBtn.disabled = isCompacting;
}

function activateTab(tabKey) {
  for (const btn of tabButtons) {
    const selected = btn.dataset.tab === tabKey;
    btn.setAttribute('aria-selected', selected ? 'true' : 'false');
    btn.tabIndex = selected ? 0 : -1;
  }
  for (const [key, panel] of Object.entries(tabPanels)) {
    panel.hidden = key !== tabKey;
  }
}

async function refreshAll() {
  if (activeAbortController) {
    activeAbortController.abort();
  }
  const controller = new AbortController();
  activeAbortController = controller;

  clearError();
  setBadge('loading', '불러오는 중');
  refreshBtn.disabled = true;

  try {
    const payload = { workspaceUris: activeWorkspaces };
    const [state, mcpSummary] = await Promise.all([
      postJson('/api/state', payload, controller.signal),
      postJson('/api/mcp/summary', payload, controller.signal),
    ]);

    if (controller.signal.aborted) {
      return;
    }

    renderList(
      pluginsListEl,
      state.plugins,
      '활성화된 플러그인이 없습니다.',
      (p) => ({ title: p.name, meta: p.isGlobal ? '전역 · 활성' : '워크스페이스 · 활성' }),
    );
    renderList(
      sidecarsListEl,
      state.sidecars,
      '실행 중인 사이드카가 없습니다.',
      (s) => ({ title: s.sidecarId, meta: s.running ? '실행 중' : '중지됨' }),
    );
    renderDiagnostics(mcpSummary, state);

    if (state.statusbarAvailable) {
      const telemetryResp = await postJson('/api/statusbar/telemetry', payload, controller.signal);
      if (controller.signal.aborted) {
        return;
      }
      renderTelemetry(telemetryResp, true);
    } else {
      renderTelemetry(null, false);
    }

    setBadge('ok', '연결됨');
  } catch (err) {
    if (err.name === 'AbortError') {
      return;
    }
    showError(err.message || '상태를 불러오지 못했습니다.');
    compactBtn.disabled = true;
  } finally {
    if (activeAbortController === controller) {
      refreshBtn.disabled = false;
    }
  }
}

async function triggerCompact() {
  if (isCompacting) {
    return;
  }
  isCompacting = true;
  compactBtn.disabled = true;
  actionFeedbackEl.textContent = '컨텍스트 정리를 요청하는 중...';
  try {
    const res = await postJson('/api/statusbar/compact', { workspaceUris: activeWorkspaces });
    actionFeedbackEl.textContent = res?.ok ? '컨텍스트 정리가 완료되었습니다.' : '컨텍스트 정리 응답을 확인하세요.';
    await refreshAll();
  } catch (err) {
    actionFeedbackEl.textContent = `컨텍스트 정리 실패: ${err.message}`;
  } finally {
    isCompacting = false;
    compactBtn.disabled = false;
  }
}

tabButtons.forEach((btn, idx) => {
  btn.addEventListener('click', () => activateTab(btn.dataset.tab));
  btn.addEventListener('keydown', (e) => {
    if (e.isComposing || e.keyCode === 229) {
      return;
    }
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      e.preventDefault();
      const delta = e.key === 'ArrowRight' ? 1 : -1;
      const next = tabButtons[(idx + delta + tabButtons.length) % tabButtons.length];
      activateTab(next.dataset.tab);
      next.focus();
    }
  });
});

refreshBtn.addEventListener('click', () => {
  void refreshAll();
});
retryBtn.addEventListener('click', () => {
  void refreshAll();
});
compactBtn.addEventListener('click', () => {
  void triggerCompact();
});

if (window.sidecar && typeof window.sidecar.onWorkspaceChange === 'function') {
  window.sidecar.onWorkspaceChange((uris) => {
    activeWorkspaces = Array.isArray(uris) ? uris : [];
    void refreshAll();
  });
}

void refreshAll();
