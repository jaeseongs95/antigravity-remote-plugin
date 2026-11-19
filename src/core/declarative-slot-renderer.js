import { createSafeElement } from '../security/dom-guard.js';
import { validateHostSurfacePort } from './ports.js';
import { resolveLocalizedText } from './remote-plugin-contract.js';

const HOST_STYLE_ID = 'remote-slot-host-css';
const HOST_SLOT_ID = 'remote-slot-host.root';

const SLOT_LABELS = Object.freeze({
  'title-bar': Object.freeze({ ko: '상단 타이틀 바', en: 'Title Bar' }),
  'status-bar': Object.freeze({ ko: '상태 표시줄', en: 'Status Bar' }),
  'composer-toolbar': Object.freeze({ ko: '입력 툴바', en: 'Composer Toolbar' }),
  sidebar: Object.freeze({ ko: '사이드바', en: 'Sidebar' }),
  'settings-pane': Object.freeze({ ko: '설정 패널', en: 'Settings Pane' }),
  'aux-pane': Object.freeze({ ko: '보조 패널', en: 'Aux Pane' }),
  overlay: Object.freeze({ ko: '오버레이', en: 'Overlay' }),
  modal: Object.freeze({ ko: '모달', en: 'Modal' }),
  theme: Object.freeze({ ko: '테마', en: 'Theme' }),
  custom: Object.freeze({ ko: '사용자 지정', en: 'Custom' }),
});

const STRINGS = Object.freeze({
  ko: Object.freeze({
    title: '원격 플러그인 호스트',
    pillLabel: '원격 플러그인 메뉴 열기',
    pillText: '플러그인',
    close: '닫기',
    refresh: '새로고침',
    empty: '연동된 RemotePlugin.v1 플러그인이 없습니다. 각 플러그인이 표준 인터페이스를 구현해 등록하면 지정된 UI 위치에 표시됩니다.',
    confirmTitle: '작업 확인 필요',
    confirmButton: '확인 후 실행',
    cancelButton: '취소',
    conflictRefresh: '다시 불러오기',
    langToggle: 'EN',
    langAria: '영어로 전환',
    snapshotError: '스냅샷 로드 오류',
    actionOk: '작업이 완료되었습니다.',
  }),
  en: Object.freeze({
    title: 'Remote Plugin Host',
    pillLabel: 'Open Remote Plugins menu',
    pillText: 'Plugins',
    close: 'Close',
    refresh: 'Refresh',
    empty: 'No RemotePlugin.v1 plugins registered yet. Plugins implementing the standard interface appear in their declared UI slots.',
    confirmTitle: 'Confirmation Required',
    confirmButton: 'Confirm',
    cancelButton: 'Cancel',
    conflictRefresh: 'Reload',
    langToggle: 'KO',
    langAria: 'Switch to Korean',
    snapshotError: 'Snapshot error',
    actionOk: 'Action completed.',
  }),
});

const HOST_CSS = [
  `:host, .rph-root { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Noto Sans KR", sans-serif; color-scheme: light dark; box-sizing: border-box; }`,
  `.rph-root * { box-sizing: border-box; }`,
  `.rph-titlebar { position: fixed; top: max(8px, env(safe-area-inset-top)); left: 50%; transform: translateX(-50%); max-width: calc(100vw - 24px); z-index: 2147482990; display: flex; flex-wrap: wrap; gap: 6px; padding: 6px 10px; border-radius: 12px; border: 1px solid rgba(128,134,139,0.35); background: var(--card, #181a1f); color: var(--foreground, #f1f3f4); box-shadow: 0 6px 20px rgba(0,0,0,0.24); }`,
  `.rph-statusbar { position: fixed; left: max(10px, env(safe-area-inset-left)); bottom: max(12px, env(safe-area-inset-bottom)); max-width: calc(100vw - 132px); z-index: 2147482990; display: flex; flex-wrap: wrap; align-items: center; gap: 6px; padding: 6px 10px; border-radius: 12px; border: 1px solid rgba(128,134,139,0.35); background: var(--card, #181a1f); color: var(--foreground, #f1f3f4); box-shadow: 0 6px 20px rgba(0,0,0,0.24); }`,
  `.rph-composerbar { position: fixed; left: max(10px, env(safe-area-inset-left)); bottom: max(68px, calc(env(safe-area-inset-bottom) + 58px)); max-width: calc(100vw - 24px); z-index: 2147482990; display: flex; flex-wrap: wrap; gap: 6px; padding: 6px 10px; border-radius: 12px; border: 1px solid rgba(128,134,139,0.35); background: var(--card, #181a1f); color: var(--foreground, #f1f3f4); box-shadow: 0 6px 20px rgba(0,0,0,0.24); }`,
  `.rph-dock { position: fixed; right: max(10px, env(safe-area-inset-right)); bottom: max(12px, env(safe-area-inset-bottom)); z-index: 2147483000; display: flex; flex-direction: column; align-items: flex-end; gap: 8px; }`,
  `.rph-pill { min-width: 44px; min-height: 44px; padding: 0 14px; border-radius: 999px; border: 1px solid rgba(128,134,139,0.35); background: var(--card, #181a1f); color: var(--foreground, #f1f3f4); font-size: 13px; font-weight: 600; cursor: pointer; display: inline-flex; align-items: center; gap: 8px; box-shadow: 0 6px 20px rgba(0,0,0,0.28); touch-action: manipulation; }`,
  `.rph-badge-count { min-width: 20px; height: 20px; padding: 0 6px; border-radius: 999px; background: #1a73e8; color: #ffffff; font-size: 11px; font-weight: 700; display: inline-flex; align-items: center; justify-content: center; }`,
  `.rph-drawer { width: min(360px, calc(100vw - 20px)); max-height: calc(100vh - 96px); max-height: calc(100dvh - 96px); overflow-y: auto; border-radius: 14px; border: 1px solid rgba(128,134,139,0.35); background: var(--card, #181a1f); color: var(--foreground, #f1f3f4); padding: 14px; box-shadow: 0 12px 32px rgba(0,0,0,0.38); display: flex; flex-direction: column; gap: 10px; }`,
  `.rph-drawer[hidden], .rph-titlebar[hidden], .rph-statusbar[hidden], .rph-composerbar[hidden], .rph-confirm[hidden] { display: none; }`,
  `.rph-header { display: flex; align-items: center; justify-content: space-between; gap: 8px; }`,
  `.rph-title { margin: 0; font-size: 14px; font-weight: 700; }`,
  `.rph-header-actions { display: inline-flex; align-items: center; gap: 6px; }`,
  `.rph-btn { min-width: 44px; min-height: 44px; padding: 8px 12px; border-radius: 10px; border: 1px solid rgba(128,134,139,0.35); background: rgba(128,134,139,0.14); color: inherit; font-size: 13px; font-weight: 600; cursor: pointer; touch-action: manipulation; }`,
  `.rph-btn[data-style="primary"] { background: #1a73e8; border-color: #1a73e8; color: #ffffff; }`,
  `.rph-btn[data-style="danger"] { background: #d93025; border-color: #d93025; color: #ffffff; }`,
  `.rph-btn:disabled { opacity: 0.5; cursor: not-allowed; }`,
  `.rph-btn:focus-visible, .rph-pill:focus-visible { outline: 2px solid #4d90fe; outline-offset: 2px; }`,
  `.rph-slot-group { border-radius: 10px; border: 1px solid rgba(128,134,139,0.24); padding: 10px; display: flex; flex-direction: column; gap: 8px; }`,
  `.rph-slot-heading { font-size: 11px; font-weight: 700; text-transform: uppercase; opacity: 0.72; letter-spacing: 0.03em; }`,
  `.rph-plugin-card { border-radius: 8px; border: 1px solid rgba(128,134,139,0.2); padding: 8px; display: flex; flex-direction: column; gap: 8px; }`,
  `.rph-plugin-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap; }`,
  `.rph-plugin-name { font-size: 13px; font-weight: 700; }`,
  `.rph-chip { display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; background: rgba(128,134,139,0.18); }`,
  `.rph-chip[data-tone="ok"] { background: rgba(52,168,83,0.22); color: #34a853; }`,
  `.rph-chip[data-tone="warn"] { background: rgba(251,188,4,0.22); color: #f29900; }`,
  `.rph-chip[data-tone="error"] { background: rgba(234,67,53,0.22); color: #ea4335; }`,
  `.rph-metrics { display: flex; flex-wrap: wrap; gap: 8px; }`,
  `.rph-metric { display: inline-flex; align-items: baseline; gap: 5px; font-size: 12px; padding: 4px 8px; border-radius: 8px; background: rgba(128,134,139,0.12); }`,
  `.rph-metric-val { font-weight: 700; }`,
  `.rph-list { display: flex; flex-direction: column; gap: 6px; margin: 0; padding: 0; list-style: none; }`,
  `.rph-list-item { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 6px 8px; border-radius: 8px; background: rgba(128,134,139,0.1); font-size: 12px; }`,
  `.rph-kv { display: flex; flex-direction: column; gap: 4px; font-size: 12px; }`,
  `.rph-kv-row { display: flex; justify-content: space-between; gap: 8px; word-break: break-word; }`,
  `.rph-actions { display: flex; flex-wrap: wrap; gap: 6px; }`,
  `.rph-notice { font-size: 12px; padding: 8px; border-radius: 8px; background: rgba(128,134,139,0.14); word-break: break-word; }`,
  `.rph-notice[data-tone="error"] { background: rgba(234,67,53,0.18); }`,
  `.rph-notice[data-tone="warn"] { background: rgba(251,188,4,0.18); }`,
  `.rph-confirm { border-radius: 10px; border: 1px solid #f29900; background: rgba(251,188,4,0.12); padding: 10px; display: flex; flex-direction: column; gap: 8px; }`,
  `.rph-status-inline { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; }`,
  `@media (prefers-color-scheme: light) { .rph-titlebar, .rph-statusbar, .rph-composerbar, .rph-pill, .rph-drawer { background: var(--card, #ffffff); color: var(--foreground, #1f2328); } }`,
].join(' ');

function clearChildren(el) {
  while (el.firstChild) {
    el.removeChild(el.firstChild);
  }
}

export function createDeclarativeSlotRenderer({
  win,
  doc,
  surface,
  registry,
  initialLocale = 'ko',
}) {
  validateHostSurfacePort(surface);
  if (!doc || typeof doc.createElement !== 'function') {
    throw new TypeError('DeclarativeSlotRenderer requires a DOM document.');
  }
  if (!registry || typeof registry.list !== 'function') {
    throw new TypeError('DeclarativeSlotRenderer requires a RemotePluginRegistry.');
  }

  let locale = initialLocale === 'en' ? 'en' : 'ko';
  let isOpen = false;
  let disposed = false;
  let renderSeq = 0;
  let pendingChallenge = null;
  const feedbackByPlugin = Object.create(null);

  surface.injectStyle(HOST_STYLE_ID, HOST_CSS);
  const slotRoot = surface.mountSlot(HOST_SLOT_ID);
  slotRoot.setAttribute('class', 'rph-root');

  const titleBarEl = createSafeElement(doc, 'div', {
    attrs: { class: 'rph-titlebar', 'data-remote-slot': 'title-bar', hidden: 'hidden' },
  });
  const statusBarEl = createSafeElement(doc, 'div', {
    attrs: { class: 'rph-statusbar', 'data-remote-slot': 'status-bar', hidden: 'hidden' },
  });
  const composerBarEl = createSafeElement(doc, 'div', {
    attrs: { class: 'rph-composerbar', 'data-remote-slot': 'composer-toolbar', hidden: 'hidden' },
  });

  const dockEl = createSafeElement(doc, 'div', { attrs: { class: 'rph-dock' } });
  const drawerEl = createSafeElement(doc, 'section', {
    attrs: {
      class: 'rph-drawer',
      role: 'dialog',
      'aria-label': STRINGS[locale].title,
      hidden: 'hidden',
    },
  });

  const headerEl = createSafeElement(doc, 'div', { attrs: { class: 'rph-header' } });
  const titleEl = createSafeElement(doc, 'h2', {
    attrs: { class: 'rph-title' },
    text: STRINGS[locale].title,
  });
  const headerActions = createSafeElement(doc, 'div', { attrs: { class: 'rph-header-actions' } });
  const langBtn = createSafeElement(doc, 'button', {
    attrs: {
      type: 'button',
      class: 'rph-btn',
      'data-rph-control': 'lang-toggle',
      'aria-label': STRINGS[locale].langAria,
    },
    text: STRINGS[locale].langToggle,
  });
  const closeBtn = createSafeElement(doc, 'button', {
    attrs: {
      type: 'button',
      class: 'rph-btn',
      'data-rph-control': 'close',
      'aria-label': STRINGS[locale].close,
    },
    text: '×',
  });
  headerActions.appendChild(langBtn);
  headerActions.appendChild(closeBtn);
  headerEl.appendChild(titleEl);
  headerEl.appendChild(headerActions);

  const confirmBoxEl = createSafeElement(doc, 'div', {
    attrs: { class: 'rph-confirm', 'data-rph-control': 'confirm-box', role: 'alertdialog', hidden: 'hidden' },
  });
  const drawerBodyEl = createSafeElement(doc, 'div', {
    attrs: { 'data-rph-control': 'drawer-body' },
  });

  drawerEl.appendChild(headerEl);
  drawerEl.appendChild(confirmBoxEl);
  drawerEl.appendChild(drawerBodyEl);

  const pillBtn = createSafeElement(doc, 'button', {
    attrs: {
      type: 'button',
      class: 'rph-pill',
      'data-rph-control': 'dock-pill',
      'aria-expanded': 'false',
      'aria-label': STRINGS[locale].pillLabel,
    },
  });
  const pillLabelSpan = createSafeElement(doc, 'span', { text: STRINGS[locale].pillText });
  const pillCountSpan = createSafeElement(doc, 'span', {
    attrs: { class: 'rph-badge-count', 'data-rph-control': 'plugin-count' },
    text: '0',
  });
  pillBtn.appendChild(pillLabelSpan);
  pillBtn.appendChild(pillCountSpan);

  dockEl.appendChild(drawerEl);
  dockEl.appendChild(pillBtn);

  slotRoot.appendChild(titleBarEl);
  slotRoot.appendChild(composerBarEl);
  slotRoot.appendChild(statusBarEl);
  slotRoot.appendChild(dockEl);

  function setOpen(nextOpen) {
    isOpen = Boolean(nextOpen);
    drawerEl.hidden = !isOpen;
    pillBtn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    if (!isOpen && typeof pillBtn.focus === 'function') {
      pillBtn.focus();
    }
  }

  function updateChromeLocale() {
    const s = STRINGS[locale];
    titleEl.textContent = s.title;
    drawerEl.setAttribute('aria-label', s.title);
    langBtn.textContent = s.langToggle;
    langBtn.setAttribute('aria-label', s.langAria);
    closeBtn.setAttribute('aria-label', s.close);
    pillBtn.setAttribute('aria-label', s.pillLabel);
    pillLabelSpan.textContent = s.pillText;
  }

  function renderConfirmBox() {
    clearChildren(confirmBoxEl);
    if (!pendingChallenge) {
      confirmBoxEl.hidden = true;
      return;
    }
    const s = STRINGS[locale];
    confirmBoxEl.hidden = false;
    confirmBoxEl.appendChild(
      createSafeElement(doc, 'div', { attrs: { class: 'rph-plugin-name' }, text: s.confirmTitle }),
    );
    confirmBoxEl.appendChild(
      createSafeElement(doc, 'div', {
        attrs: { class: 'rph-notice', 'data-tone': 'warn' },
        text: resolveLocalizedText(pendingChallenge.message, locale),
      }),
    );
    const btnRow = createSafeElement(doc, 'div', { attrs: { class: 'rph-actions' } });
    const confirmBtn = createSafeElement(doc, 'button', {
      attrs: {
        type: 'button',
        class: 'rph-btn',
        'data-style': 'danger',
        'data-rph-control': 'confirm-accept',
      },
      text: pendingChallenge.confirmLabel
        ? resolveLocalizedText(pendingChallenge.confirmLabel, locale)
        : s.confirmButton,
    });
    const cancelBtn = createSafeElement(doc, 'button', {
      attrs: {
        type: 'button',
        class: 'rph-btn',
        'data-rph-control': 'confirm-cancel',
      },
      text: s.cancelButton,
    });
    confirmBtn.addEventListener('click', () => {
      const active = pendingChallenge;
      pendingChallenge = null;
      renderConfirmBox();
      if (active) {
        void executePluginAction(active.pluginId, active.actionId, {
          expectedRevision: active.expectedRevision,
          challengeResponse: { challengeId: active.challengeId, confirmed: true },
        });
      }
    });
    cancelBtn.addEventListener('click', () => {
      pendingChallenge = null;
      renderConfirmBox();
    });
    btnRow.appendChild(confirmBtn);
    btnRow.appendChild(cancelBtn);
    confirmBoxEl.appendChild(btnRow);
  }

  async function executePluginAction(pluginId, actionId, invocation = {}) {
    const result = await registry.invokeAction(pluginId, actionId, invocation, { locale });
    if (disposed) {
      return result;
    }
    if (result.status === 'confirmation_required') {
      pendingChallenge = {
        pluginId,
        actionId,
        expectedRevision: invocation.expectedRevision,
        challengeId: result.challengeId,
        message: result.message,
        confirmLabel: result.confirmLabel,
      };
      setOpen(true);
      renderConfirmBox();
      return result;
    }
    if (result.status === 'conflict') {
      feedbackByPlugin[pluginId] = {
        tone: 'warn',
        text: resolveLocalizedText(result.message, locale),
        needsRefresh: true,
      };
    } else if (result.status === 'error') {
      feedbackByPlugin[pluginId] = {
        tone: 'error',
        text: resolveLocalizedText(result.message, locale),
        needsRefresh: false,
      };
    } else {
      feedbackByPlugin[pluginId] = {
        tone: 'ok',
        text: result.message ? resolveLocalizedText(result.message, locale) : STRINGS[locale].actionOk,
        needsRefresh: false,
      };
    }
    await render();
    return result;
  }

  function renderSection(pluginId, snapshotRevision, section) {
    if (section.kind === 'notice') {
      return createSafeElement(doc, 'div', {
        attrs: { class: 'rph-notice', 'data-tone': section.tone },
        text: resolveLocalizedText(section.text, locale),
      });
    }
    if (section.kind === 'metrics') {
      const wrap = createSafeElement(doc, 'div', { attrs: { class: 'rph-metrics' } });
      for (const item of section.items) {
        const box = createSafeElement(doc, 'span', {
          attrs: { class: 'rph-metric', 'data-tone': item.tone },
        });
        box.appendChild(createSafeElement(doc, 'span', { text: resolveLocalizedText(item.label, locale) }));
        box.appendChild(createSafeElement(doc, 'span', { attrs: { class: 'rph-metric-val' }, text: item.value }));
        wrap.appendChild(box);
      }
      return wrap;
    }
    if (section.kind === 'list') {
      const box = createSafeElement(doc, 'div', { attrs: { class: 'rph-kv' } });
      if (section.title) {
        box.appendChild(createSafeElement(doc, 'div', { attrs: { class: 'rph-slot-heading' }, text: resolveLocalizedText(section.title, locale) }));
      }
      const ul = createSafeElement(doc, 'ul', { attrs: { class: 'rph-list' } });
      for (const item of section.items) {
        const li = createSafeElement(doc, 'li', { attrs: { class: 'rph-list-item' } });
        const left = createSafeElement(doc, 'div');
        left.appendChild(createSafeElement(doc, 'div', { text: resolveLocalizedText(item.primary, locale) }));
        if (item.secondary) {
          left.appendChild(createSafeElement(doc, 'div', { attrs: { class: 'rph-slot-heading' }, text: resolveLocalizedText(item.secondary, locale) }));
        }
        li.appendChild(left);
        if (item.badge) {
          li.appendChild(createSafeElement(doc, 'span', { attrs: { class: 'rph-chip' }, text: resolveLocalizedText(item.badge, locale) }));
        }
        ul.appendChild(li);
      }
      box.appendChild(ul);
      return box;
    }
    if (section.kind === 'key-value') {
      const box = createSafeElement(doc, 'div', { attrs: { class: 'rph-kv' } });
      if (section.title) {
        box.appendChild(createSafeElement(doc, 'div', { attrs: { class: 'rph-slot-heading' }, text: resolveLocalizedText(section.title, locale) }));
      }
      for (const entry of section.entries) {
        const row = createSafeElement(doc, 'div', { attrs: { class: 'rph-kv-row' } });
        row.appendChild(createSafeElement(doc, 'span', { text: resolveLocalizedText(entry.key, locale) }));
        row.appendChild(createSafeElement(doc, 'strong', { text: entry.value }));
        box.appendChild(row);
      }
      return box;
    }
    if (section.kind === 'actions') {
      const box = createSafeElement(doc, 'div', { attrs: { class: 'rph-kv' } });
      if (section.title) {
        box.appendChild(createSafeElement(doc, 'div', { attrs: { class: 'rph-slot-heading' }, text: resolveLocalizedText(section.title, locale) }));
      }
      const row = createSafeElement(doc, 'div', { attrs: { class: 'rph-actions' } });
      for (const item of section.items) {
        const attrs = {
          type: 'button',
          class: 'rph-btn',
          'data-style': item.style,
          'data-plugin-id': pluginId,
          'data-action-id': item.id,
        };
        if (item.disabled) {
          attrs.disabled = 'disabled';
        }
        const btn = createSafeElement(doc, 'button', {
          attrs,
          text: resolveLocalizedText(item.label, locale),
        });
        btn.addEventListener('click', () => {
          void executePluginAction(
            pluginId,
            item.id,
            snapshotRevision ? { expectedRevision: snapshotRevision } : {},
          );
        });
        row.appendChild(btn);
      }
      box.appendChild(row);
      return box;
    }
    return createSafeElement(doc, 'div');
  }

  function renderInlineBarPlugin(container, plugin, snapResult) {
    const itemWrap = createSafeElement(doc, 'div', {
      attrs: {
        class: 'rph-status-inline',
        'data-plugin-id': plugin.id,
        'data-slot-id': plugin.uiSlot.slotId,
      },
    });
    itemWrap.appendChild(
      createSafeElement(doc, 'span', {
        attrs: { class: 'rph-plugin-name' },
        text: resolveLocalizedText(plugin.displayName, locale),
      }),
    );
    if (!snapResult.ok) {
      itemWrap.appendChild(
        createSafeElement(doc, 'span', {
          attrs: { class: 'rph-chip', 'data-tone': 'error' },
          text: STRINGS[locale].snapshotError,
        }),
      );
      container.appendChild(itemWrap);
      return;
    }
    const { snapshot } = snapResult;
    if (snapshot.badge) {
      itemWrap.appendChild(
        createSafeElement(doc, 'span', {
          attrs: { class: 'rph-chip', 'data-tone': snapshot.badge.tone },
          text: resolveLocalizedText(snapshot.badge.text, locale),
        }),
      );
    }
    for (const sec of snapshot.sections) {
      if (sec.kind === 'metrics') {
        itemWrap.appendChild(renderSection(plugin.id, snapshot.revision, sec));
      } else if (sec.kind === 'actions') {
        itemWrap.appendChild(renderSection(plugin.id, snapshot.revision, sec));
      }
    }
    container.appendChild(itemWrap);
  }

  function renderPluginCard(plugin, snapResult) {
    const card = createSafeElement(doc, 'article', {
      attrs: {
        class: 'rph-plugin-card',
        'data-plugin-id': plugin.id,
        'data-slot-id': plugin.uiSlot.slotId,
      },
    });
    const head = createSafeElement(doc, 'div', { attrs: { class: 'rph-plugin-head' } });
    head.appendChild(
      createSafeElement(doc, 'span', {
        attrs: { class: 'rph-plugin-name' },
        text: resolveLocalizedText(plugin.displayName, locale),
      }),
    );
    if (snapResult.ok && snapResult.snapshot.badge) {
      head.appendChild(
        createSafeElement(doc, 'span', {
          attrs: { class: 'rph-chip', 'data-tone': snapResult.snapshot.badge.tone },
          text: resolveLocalizedText(snapResult.snapshot.badge.text, locale),
        }),
      );
    }
    card.appendChild(head);

    if (!snapResult.ok) {
      card.appendChild(
        createSafeElement(doc, 'div', {
          attrs: { class: 'rph-notice', 'data-tone': 'error' },
          text: `${STRINGS[locale].snapshotError}: ${snapResult.error}`,
        }),
      );
      return card;
    }

    const { snapshot } = snapResult;
    if (snapshot.notice) {
      card.appendChild(
        createSafeElement(doc, 'div', {
          attrs: { class: 'rph-notice', 'data-tone': snapshot.notice.tone },
          text: resolveLocalizedText(snapshot.notice.text, locale),
        }),
      );
    }
    for (const sec of snapshot.sections) {
      card.appendChild(renderSection(plugin.id, snapshot.revision, sec));
    }

    const fb = feedbackByPlugin[plugin.id];
    if (fb) {
      const fbEl = createSafeElement(doc, 'div', {
        attrs: { class: 'rph-notice', 'data-tone': fb.tone, role: 'status', 'aria-live': 'polite' },
        text: fb.text,
      });
      card.appendChild(fbEl);
      if (fb.needsRefresh) {
        const reloadBtn = createSafeElement(doc, 'button', {
          attrs: { type: 'button', class: 'rph-btn', 'data-rph-control': 'conflict-reload' },
          text: STRINGS[locale].conflictRefresh,
        });
        reloadBtn.addEventListener('click', () => {
          delete feedbackByPlugin[plugin.id];
          void render();
        });
        card.appendChild(reloadBtn);
      }
    }
    return card;
  }

  async function render() {
    if (disposed) {
      return;
    }
    const seq = ++renderSeq;
    const plugins = registry.list();
    const snapshots = await Promise.all(
      plugins.map(async (plugin) => ({
        plugin,
        snapResult: await registry.readSnapshot(plugin.id, { locale }),
      })),
    );
    if (disposed || seq !== renderSeq) {
      return;
    }

    updateChromeLocale();
    renderConfirmBox();
    pillCountSpan.textContent = String(plugins.length);

    clearChildren(titleBarEl);
    clearChildren(statusBarEl);
    clearChildren(composerBarEl);
    clearChildren(drawerBodyEl);

    const drawerGroups = Object.create(null);
    let titleBarCount = 0;
    let statusBarCount = 0;
    let composerBarCount = 0;

    for (const entry of snapshots) {
      const slot = entry.plugin.uiSlot.slot;
      if (slot === 'title-bar') {
        renderInlineBarPlugin(titleBarEl, entry.plugin, entry.snapResult);
        titleBarCount += 1;
      } else if (slot === 'status-bar') {
        renderInlineBarPlugin(statusBarEl, entry.plugin, entry.snapResult);
        statusBarCount += 1;
      } else if (slot === 'composer-toolbar') {
        renderInlineBarPlugin(composerBarEl, entry.plugin, entry.snapResult);
        composerBarCount += 1;
      }

      if (!drawerGroups[slot]) {
        drawerGroups[slot] = [];
      }
      drawerGroups[slot].push(entry);
    }

    titleBarEl.hidden = titleBarCount === 0;
    statusBarEl.hidden = statusBarCount === 0;
    composerBarEl.hidden = composerBarCount === 0;

    const slotKeys = Object.keys(drawerGroups);
    if (slotKeys.length === 0) {
      drawerBodyEl.appendChild(
        createSafeElement(doc, 'div', {
          attrs: { class: 'rph-notice', 'data-tone': 'info' },
          text: STRINGS[locale].empty,
        }),
      );
      return;
    }

    for (const slot of slotKeys) {
      const groupEl = createSafeElement(doc, 'div', {
        attrs: { class: 'rph-slot-group', 'data-remote-slot-group': slot },
      });
      const labelObj = SLOT_LABELS[slot] || { ko: slot, en: slot };
      groupEl.appendChild(
        createSafeElement(doc, 'div', {
          attrs: { class: 'rph-slot-heading' },
          text: `${resolveLocalizedText(labelObj, locale)} (${slot})`,
        }),
      );
      for (const entry of drawerGroups[slot]) {
        groupEl.appendChild(renderPluginCard(entry.plugin, entry.snapResult));
      }
      drawerBodyEl.appendChild(groupEl);
    }
  }

  const onPillClick = () => setOpen(!isOpen);
  const onCloseClick = () => setOpen(false);
  const onLangClick = () => {
    locale = locale === 'ko' ? 'en' : 'ko';
    void render();
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
  langBtn.addEventListener('click', onLangClick);
  if (win && typeof win.addEventListener === 'function') {
    win.addEventListener('keydown', onKeyDown);
  }
  const unsubRegistry = registry.onChange(() => {
    void render();
  });

  const dispose = () => {
    if (disposed) {
      return;
    }
    disposed = true;
    unsubRegistry();
    pillBtn.removeEventListener('click', onPillClick);
    closeBtn.removeEventListener('click', onCloseClick);
    langBtn.removeEventListener('click', onLangClick);
    if (win && typeof win.removeEventListener === 'function') {
      win.removeEventListener('keydown', onKeyDown);
    }
    surface.removeStyle(HOST_STYLE_ID);
    surface.unmountSlot(HOST_SLOT_ID);
  };

  surface.onDispose(dispose);
  void render();

  return Object.freeze({
    render,
    setOpen,
    toggleOpen() {
      setOpen(!isOpen);
    },
    setLocale(nextLocale) {
      locale = nextLocale === 'en' ? 'en' : 'ko';
      return render();
    },
    getLocale() {
      return locale;
    },
    isOpen() {
      return isOpen;
    },
    getSlotRoot() {
      return slotRoot;
    },
    dispose,
  });
}
