import { createSafeElement } from '../security/dom-guard.js';
import { validateHostSurfacePort } from './ports.js';
import { ALLOWED_UI_SLOTS, REMOTE_PLUGIN_CONTRACT_VERSION } from './remote-plugin-contract.js';

const PANEL_STYLE_ID = 'desktop-remote-companion-css';

const PANEL_CSS = [
  `.drc-panel { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Noto Sans KR", sans-serif; border-radius: 12px; border: 1px solid rgba(128,134,139,0.3); padding: 14px; display: flex; flex-direction: column; gap: 10px; max-width: 680px; }`,
  `.drc-header { display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap; }`,
  `.drc-title { margin: 0; font-size: 15px; font-weight: 700; }`,
  `.drc-subtitle { margin: 0; font-size: 12px; opacity: 0.78; }`,
  `.drc-card { border-radius: 8px; border: 1px solid rgba(128,134,139,0.22); padding: 10px; display: flex; flex-direction: column; gap: 8px; }`,
  `.drc-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap; font-size: 13px; }`,
  `.drc-slots { display: flex; flex-wrap: wrap; gap: 6px; }`,
  `.drc-chip { padding: 3px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; background: rgba(128,134,139,0.16); }`,
  `.drc-btn { min-height: 36px; padding: 6px 12px; border-radius: 8px; border: 1px solid rgba(128,134,139,0.35); background: rgba(128,134,139,0.14); color: inherit; font-size: 12px; font-weight: 600; cursor: pointer; }`,
  `.drc-btn:focus-visible { outline: 2px solid #4d90fe; outline-offset: 2px; }`,
  `.drc-status { font-size: 12px; opacity: 0.85; min-height: 18px; }`,
].join(' ');

const COPY = Object.freeze({
  ko: Object.freeze({
    title: '원격 플러그인 컴패니언',
    subtitle: 'AddonManifest.v1 호스트 격리 슬롯에서 동작하는 원격 연동 안내 패널입니다.',
    langToggle: 'EN',
    contractLabel: '원격 플러그인 표준 계약',
    hostLabel: '네이티브 호스트 프로필',
    setupTitle: '외부 · 모바일 브라우저 원격 연동',
    copyBookmarklet: '북마클릿 복사',
    copyUserscript: '유저스크립트 경로 복사',
    copiedBookmarklet: '북마클릿 스니펫을 클립보드에 복사했습니다.',
    copiedUserscript: '유저스크립트 경로를 클립보드에 복사했습니다.',
    copyFailed: '클립보드 복사에 실패했습니다. 배포 파일을 직접 열어 복사하세요.',
    slotsTitle: '지원되는 원격 UI 슬롯 배치',
  }),
  en: Object.freeze({
    title: 'Remote Plugin Companion',
    subtitle: 'Remote integration settings panel running inside an isolated AddonManifest.v1 slot.',
    langToggle: 'KO',
    contractLabel: 'Remote Plugin Standard',
    hostLabel: 'Native Host Profile',
    setupTitle: 'External & Mobile Browser Setup',
    copyBookmarklet: 'Copy Bookmarklet',
    copyUserscript: 'Copy Userscript Path',
    copiedBookmarklet: 'Bookmarklet snippet copied to clipboard.',
    copiedUserscript: 'Userscript path copied to clipboard.',
    copyFailed: 'Clipboard copy failed. Copy directly from the built dist artifact.',
    slotsTitle: 'Supported Remote UI Slot Placements',
  }),
});

export function mountDesktopCompanionView({
  doc,
  surface,
  slotId,
  hostInfo = {},
  remoteArtifacts = {},
  clipboard = null,
  initialLocale = 'ko',
}) {
  validateHostSurfacePort(surface);
  if (!doc || typeof doc.createElement !== 'function') {
    throw new TypeError('DesktopCompanionView requires a DOM document.');
  }
  if (typeof slotId !== 'string' || !slotId.trim()) {
    throw new TypeError('DesktopCompanionView requires a declared slotId.');
  }

  let locale = initialLocale === 'en' ? 'en' : 'ko';
  let statusMessage = '';
  let disposed = false;

  surface.injectStyle(PANEL_STYLE_ID, PANEL_CSS);
  const container = surface.mountSlot(slotId);

  const bookmarkletText =
    typeof remoteArtifacts.bookmarklet === 'string' && remoteArtifacts.bookmarklet.trim()
      ? remoteArtifacts.bookmarklet.trim()
      : 'dist/bookmarklet.txt';
  const userscriptPath =
    typeof remoteArtifacts.userscriptPath === 'string' && remoteArtifacts.userscriptPath.trim()
      ? remoteArtifacts.userscriptPath.trim()
      : 'dist/remote-companion.user.js';

  async function copyText(text, successKey) {
    if (!clipboard || typeof clipboard.writeText !== 'function') {
      statusMessage = COPY[locale].copyFailed;
      render();
      return false;
    }
    try {
      await clipboard.writeText(text);
      statusMessage = COPY[locale][successKey];
      render();
      return true;
    } catch (_err) {
      statusMessage = COPY[locale].copyFailed;
      render();
      return false;
    }
  }

  function render() {
    if (disposed) {
      return;
    }
    while (container.firstChild) {
      container.removeChild(container.firstChild);
    }

    const s = COPY[locale];
    const panel = createSafeElement(doc, 'section', {
      attrs: { class: 'drc-panel', 'data-drc-locale': locale },
    });

    const header = createSafeElement(doc, 'div', { attrs: { class: 'drc-header' } });
    const headingWrap = createSafeElement(doc, 'div');
    headingWrap.appendChild(createSafeElement(doc, 'h3', { attrs: { class: 'drc-title' }, text: s.title }));
    headingWrap.appendChild(createSafeElement(doc, 'p', { attrs: { class: 'drc-subtitle' }, text: s.subtitle }));

    const langBtn = createSafeElement(doc, 'button', {
      attrs: { type: 'button', class: 'drc-btn', 'data-drc-action': 'toggle-locale' },
      text: s.langToggle,
    });
    langBtn.addEventListener('click', () => {
      locale = locale === 'ko' ? 'en' : 'ko';
      statusMessage = '';
      render();
    });
    header.appendChild(headingWrap);
    header.appendChild(langBtn);
    panel.appendChild(header);

    const metaCard = createSafeElement(doc, 'div', { attrs: { class: 'drc-card' } });
    const row1 = createSafeElement(doc, 'div', { attrs: { class: 'drc-row' } });
    row1.appendChild(createSafeElement(doc, 'span', { text: s.contractLabel }));
    row1.appendChild(createSafeElement(doc, 'strong', { text: REMOTE_PLUGIN_CONTRACT_VERSION }));
    const row2 = createSafeElement(doc, 'div', { attrs: { class: 'drc-row' } });
    row2.appendChild(createSafeElement(doc, 'span', { text: s.hostLabel }));
    row2.appendChild(
      createSafeElement(doc, 'strong', {
        text: `${hostInfo.hostProfileId || 'default'} (${hostInfo.hostVersion || '1.0.1'})`,
      }),
    );
    metaCard.appendChild(row1);
    metaCard.appendChild(row2);
    panel.appendChild(metaCard);

    const setupCard = createSafeElement(doc, 'div', { attrs: { class: 'drc-card' } });
    setupCard.appendChild(createSafeElement(doc, 'strong', { text: s.setupTitle }));
    const btnRow = createSafeElement(doc, 'div', { attrs: { class: 'drc-slots' } });
    const copyBmBtn = createSafeElement(doc, 'button', {
      attrs: { type: 'button', class: 'drc-btn', 'data-drc-action': 'copy-bookmarklet' },
      text: s.copyBookmarklet,
    });
    copyBmBtn.addEventListener('click', () => {
      void copyText(bookmarkletText, 'copiedBookmarklet');
    });
    const copyUsBtn = createSafeElement(doc, 'button', {
      attrs: { type: 'button', class: 'drc-btn', 'data-drc-action': 'copy-userscript' },
      text: s.copyUserscript,
    });
    copyUsBtn.addEventListener('click', () => {
      void copyText(userscriptPath, 'copiedUserscript');
    });
    btnRow.appendChild(copyBmBtn);
    btnRow.appendChild(copyUsBtn);
    setupCard.appendChild(btnRow);
    setupCard.appendChild(
      createSafeElement(doc, 'div', {
        attrs: { class: 'drc-status', role: 'status', 'aria-live': 'polite', 'data-drc-status': 'true' },
        text: statusMessage,
      }),
    );
    panel.appendChild(setupCard);

    const slotCard = createSafeElement(doc, 'div', { attrs: { class: 'drc-card' } });
    slotCard.appendChild(createSafeElement(doc, 'strong', { text: s.slotsTitle }));
    const chips = createSafeElement(doc, 'div', { attrs: { class: 'drc-slots' } });
    for (const slot of ALLOWED_UI_SLOTS) {
      chips.appendChild(createSafeElement(doc, 'span', { attrs: { class: 'drc-chip' }, text: slot }));
    }
    slotCard.appendChild(chips);
    panel.appendChild(slotCard);

    container.appendChild(panel);
  }

  const dispose = () => {
    if (disposed) {
      return;
    }
    disposed = true;
    surface.removeStyle(PANEL_STYLE_ID);
    surface.unmountSlot(slotId);
  };

  surface.onDispose(dispose);
  render();

  return Object.freeze({
    render,
    setLocale(nextLocale) {
      locale = nextLocale === 'en' ? 'en' : 'ko';
      render();
    },
    getLocale() {
      return locale;
    },
    dispose,
  });
}
