import { createSafeElement } from '../../security/dom-guard.js';

const DOCK_STYLE_ID = 'arp-remote-dock-style-v2';
const DOCK_ROOT_ID = 'arp-remote-dock-root-v2';

const DOCK_CSS = [
  `#${DOCK_ROOT_ID} { position: fixed; right: max(12px, env(safe-area-inset-right)); bottom: max(14px, env(safe-area-inset-bottom)); z-index: 2147483000; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Noto Sans KR", sans-serif; color-scheme: light dark; }`,
  `#${DOCK_ROOT_ID} * { box-sizing: border-box; }`,
  `#${DOCK_ROOT_ID} .arp-pill { min-width: 44px; min-height: 44px; padding: 0 14px; border-radius: 999px; border: 1px solid rgba(128, 134, 139, 0.35); background: var(--card, #181a1f); color: var(--foreground, #f1f3f4); font-size: 13px; font-weight: 600; cursor: pointer; display: inline-flex; align-items: center; gap: 8px; box-shadow: 0 6px 20px rgba(0, 0, 0, 0.28); touch-action: manipulation; }`,
  `#${DOCK_ROOT_ID} .arp-dot { width: 8px; height: 8px; border-radius: 50%; background: #34a853; flex-shrink: 0; }`,
  `#${DOCK_ROOT_ID} .arp-dot[data-off="true"] { background: #9aa0a6; }`,
  `#${DOCK_ROOT_ID} .arp-popover { position: absolute; right: 0; bottom: 54px; width: min(320px, calc(100vw - 24px)); max-height: calc(100vh - 96px); overflow-y: auto; border-radius: 14px; border: 1px solid rgba(128, 134, 139, 0.35); background: var(--card, #181a1f); color: var(--foreground, #f1f3f4); padding: 14px; box-shadow: 0 12px 32px rgba(0, 0, 0, 0.36); display: flex; flex-direction: column; gap: 10px; }`,
  `#${DOCK_ROOT_ID} .arp-popover[hidden] { display: none; }`,
  `#${DOCK_ROOT_ID} .arp-header { display: flex; align-items: center; justify-content: space-between; gap: 8px; }`,
  `#${DOCK_ROOT_ID} .arp-title { margin: 0; font-size: 14px; font-weight: 700; }`,
  `#${DOCK_ROOT_ID} .arp-close { min-width: 44px; min-height: 44px; border-radius: 10px; border: 1px solid rgba(128, 134, 139, 0.3); background: transparent; color: inherit; font-size: 16px; cursor: pointer; touch-action: manipulation; }`,
  `#${DOCK_ROOT_ID} .arp-section { border-radius: 10px; border: 1px solid rgba(128, 134, 139, 0.24); padding: 10px; display: flex; flex-direction: column; gap: 8px; }`,
  `#${DOCK_ROOT_ID} .arp-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap; }`,
  `#${DOCK_ROOT_ID} .arp-label { font-size: 13px; font-weight: 600; }`,
  `#${DOCK_ROOT_ID} .arp-meta { font-size: 12px; opacity: 0.78; }`,
  `#${DOCK_ROOT_ID} .arp-btn { min-height: 44px; padding: 8px 12px; border-radius: 10px; border: 1px solid rgba(128, 134, 139, 0.35); background: rgba(128, 134, 139, 0.14); color: inherit; font-size: 13px; font-weight: 600; cursor: pointer; touch-action: manipulation; }`,
  `#${DOCK_ROOT_ID} .arp-btn[data-active="true"] { background: #1a73e8; border-color: #1a73e8; color: #ffffff; }`,
  `#${DOCK_ROOT_ID} .arp-pill:focus-visible, #${DOCK_ROOT_ID} .arp-close:focus-visible, #${DOCK_ROOT_ID} .arp-btn:focus-visible { outline: 2px solid #4d90fe; outline-offset: 2px; }`,
  `@media (prefers-color-scheme: light) { #${DOCK_ROOT_ID} .arp-pill, #${DOCK_ROOT_ID} .arp-popover { background: var(--card, #ffffff); color: var(--foreground, #1f2328); } }`,
].join(' ');

export function createRemoteDockUi({
  win,
  doc,
  initialTranslateEnabled = true,
  onToggleTranslation,
  onOpenSidecar,
} = {}) {
  const existing = doc.getElementById(DOCK_ROOT_ID);
  if (existing && typeof existing.remove === 'function') {
    existing.remove();
  }

  let styleEl = doc.getElementById(DOCK_STYLE_ID);
  if (!styleEl) {
    styleEl = doc.createElement('style');
    styleEl.id = DOCK_STYLE_ID;
    styleEl.textContent = DOCK_CSS;
    (doc.head || doc.documentElement).appendChild(styleEl);
  }

  let isOpen = false;
  let translateEnabled = Boolean(initialTranslateEnabled);

  const root = createSafeElement(doc, 'div', {
    attrs: { id: DOCK_ROOT_ID, 'data-remote-dock-ignore': 'true' },
  });

  const popover = createSafeElement(doc, 'section', {
    attrs: {
      class: 'arp-popover',
      role: 'dialog',
      'aria-label': 'Antigravity Remote Companion',
      hidden: 'hidden',
    },
  });

  const header = createSafeElement(doc, 'div', { attrs: { class: 'arp-header' } });
  const title = createSafeElement(doc, 'h2', {
    attrs: { class: 'arp-title' },
    text: 'Antigravity Remote',
  });
  const closeBtn = createSafeElement(doc, 'button', {
    attrs: { type: 'button', class: 'arp-close', 'aria-label': '닫기' },
    text: '×',
  });
  header.appendChild(title);
  header.appendChild(closeBtn);
  popover.appendChild(header);

  // 1) ko-thought-translator section
  const trSection = createSafeElement(doc, 'div', { attrs: { class: 'arp-section' } });
  const trRow = createSafeElement(doc, 'div', { attrs: { class: 'arp-row' } });
  const trLabel = createSafeElement(doc, 'span', {
    attrs: { class: 'arp-label' },
    text: '한글 번역 (ko-translator)',
  });
  const trToggleBtn = createSafeElement(doc, 'button', {
    attrs: {
      type: 'button',
      class: 'arp-btn',
      id: 'arp-toggle-translate',
      'data-active': translateEnabled ? 'true' : 'false',
      'aria-pressed': translateEnabled ? 'true' : 'false',
    },
    text: translateEnabled ? '켜짐' : '꺼짐',
  });
  trRow.appendChild(trLabel);
  trRow.appendChild(trToggleBtn);
  const trStatus = createSafeElement(doc, 'div', {
    attrs: { class: 'arp-meta', id: 'arp-translate-status', role: 'status', 'aria-live': 'polite' },
    text: translateEnabled ? '원격 페이지 실시간 번역 활성' : '원문 표시 중',
  });
  trSection.appendChild(trRow);
  trSection.appendChild(trStatus);
  popover.appendChild(trSection);

  // 2) antigravity-statusbar & antigravity-mcp-manager companion actions
  const sidecarSection = createSafeElement(doc, 'div', { attrs: { class: 'arp-section' } });
  const sidecarLabel = createSafeElement(doc, 'span', {
    attrs: { class: 'arp-label' },
    text: '동반 사이드카 패널',
  });
  const sidecarRow = createSafeElement(doc, 'div', { attrs: { class: 'arp-row' } });
  const statusbarBtn = createSafeElement(doc, 'button', {
    attrs: { type: 'button', class: 'arp-btn', id: 'arp-open-statusbar' },
    text: 'Statusbar 열기',
  });
  const mcpBtn = createSafeElement(doc, 'button', {
    attrs: { type: 'button', class: 'arp-btn', id: 'arp-open-mcp' },
    text: 'MCP Manager 열기',
  });
  sidecarRow.appendChild(statusbarBtn);
  sidecarRow.appendChild(mcpBtn);
  const sidecarFeedback = createSafeElement(doc, 'div', {
    attrs: { class: 'arp-meta', id: 'arp-sidecar-feedback', role: 'status', 'aria-live': 'polite' },
    text: 'Antigravity 공식 AUX_PANE 게이트웨이로 연결됩니다.',
  });
  sidecarSection.appendChild(sidecarLabel);
  sidecarSection.appendChild(sidecarRow);
  sidecarSection.appendChild(sidecarFeedback);
  popover.appendChild(sidecarSection);

  const pillBtn = createSafeElement(doc, 'button', {
    attrs: {
      type: 'button',
      class: 'arp-pill',
      id: 'arp-dock-pill',
      'aria-expanded': 'false',
      'aria-label': 'Antigravity Remote 메뉴 열기',
    },
  });
  const dot = createSafeElement(doc, 'span', {
    attrs: { class: 'arp-dot', 'data-off': translateEnabled ? 'false' : 'true' },
  });
  const pillText = createSafeElement(doc, 'span', { text: 'Remote' });
  pillBtn.appendChild(dot);
  pillBtn.appendChild(pillText);

  root.appendChild(popover);
  root.appendChild(pillBtn);
  (doc.body || doc.documentElement).appendChild(root);

  function setOpen(nextOpen) {
    isOpen = Boolean(nextOpen);
    popover.hidden = !isOpen;
    pillBtn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    if (!isOpen && typeof pillBtn.focus === 'function') {
      pillBtn.focus();
    }
  }

  function updateTranslateUi(enabled, statusText) {
    translateEnabled = Boolean(enabled);
    trToggleBtn.setAttribute('data-active', translateEnabled ? 'true' : 'false');
    trToggleBtn.setAttribute('aria-pressed', translateEnabled ? 'true' : 'false');
    trToggleBtn.textContent = translateEnabled ? '켜짐' : '꺼짐';
    dot.setAttribute('data-off', translateEnabled ? 'false' : 'true');
    if (typeof statusText === 'string') {
      trStatus.textContent = statusText;
    }
  }

  const onPillClick = () => setOpen(!isOpen);
  const onCloseClick = () => setOpen(false);
  const onTranslateClick = () => {
    const next = !translateEnabled;
    updateTranslateUi(next, next ? '번역 적용 중...' : '원문으로 복원됨');
    if (typeof onToggleTranslation === 'function') {
      onToggleTranslation(next);
    }
  };
  const onStatusbarClick = () => {
    if (typeof onOpenSidecar === 'function') {
      onOpenSidecar('antigravity-statusbar/statusbar');
    }
    sidecarFeedback.textContent = 'Statusbar 보조 패널 토글 요청을 보냈습니다.';
  };
  const onMcpClick = () => {
    if (typeof onOpenSidecar === 'function') {
      onOpenSidecar('antigravity-mcp-manager/mcp_manager');
    }
    sidecarFeedback.textContent = 'MCP Manager 보조 패널 토글 요청을 보냈습니다.';
  };
  const onKeyDown = (e) => {
    if (e.isComposing || e.keyCode === 229) {
      return;
    }
    if (e.key === 'Escape' && isOpen) {
      setOpen(false);
    }
  };

  pillBtn.addEventListener('click', onPillClick);
  closeBtn.addEventListener('click', onCloseClick);
  trToggleBtn.addEventListener('click', onTranslateClick);
  statusbarBtn.addEventListener('click', onStatusbarClick);
  mcpBtn.addEventListener('click', onMcpClick);
  win.addEventListener('keydown', onKeyDown);

  return {
    setOpen,
    toggleOpen() {
      setOpen(!isOpen);
    },
    setTranslationStatus(stats) {
      if (!stats) {
        return;
      }
      if (!stats.enabled) {
        updateTranslateUi(false, '원문 표시 중');
        return;
      }
      if (stats.lastError) {
        updateTranslateUi(true, `번역 오류: ${stats.lastError}`);
        return;
      }
      updateTranslateUi(true, `번역 활성 · ${stats.translatedCount || 0}개 구간 번역됨`);
    },
    dispose() {
      pillBtn.removeEventListener('click', onPillClick);
      closeBtn.removeEventListener('click', onCloseClick);
      trToggleBtn.removeEventListener('click', onTranslateClick);
      statusbarBtn.removeEventListener('click', onStatusbarClick);
      mcpBtn.removeEventListener('click', onMcpClick);
      win.removeEventListener('keydown', onKeyDown);
      if (typeof root.remove === 'function') {
        root.remove();
      }
    },
  };
}
