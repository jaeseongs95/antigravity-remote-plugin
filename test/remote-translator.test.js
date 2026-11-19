import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createRemoteTranslatorEngine,
  protectTechnicalTokens,
  restoreTechnicalTokens,
} from '../src/bridges/remote-translator-engine.js';

function makeNode(tagName, { attrs = {}, className = '', children = [] } = {}) {
  const el = {
    nodeType: 1,
    tagName: tagName.toUpperCase(),
    className,
    childNodes: [],
    parentElement: null,
    parentNode: null,
    getAttribute(name) {
      return Object.prototype.hasOwnProperty.call(attrs, name) ? attrs[name] : null;
    },
  };
  for (const child of children) {
    child.parentElement = el;
    child.parentNode = el;
    el.childNodes.push(child);
  }
  return el;
}

function makeText(text) {
  return {
    nodeType: 3,
    nodeValue: text,
    parentElement: null,
    parentNode: null,
  };
}

test('ARP-TC-025: createRemoteTranslatorEngine translates prose, protects inline tokens, excludes code/inputs/dock, and restores originals on OFF/dispose', async () => {
  // 1) Technical token protection round-trip.
  const { masked, tokens } = protectTechnicalTokens(
    'Check `npm run verify` at https://example.com/docs and /src/core/orchestrator.js now.',
  );
  assert.equal(tokens.length, 3);
  assert.ok(!masked.includes('npm run verify'));
  assert.equal(
    restoreTechnicalTokens(`확인 ${masked}`, tokens),
    '확인 Check `npm run verify` at https://example.com/docs and /src/core/orchestrator.js now.',
  );

  // 2) Full DOM walk, exclusion rules, dynamic MutationObserver, and restore.
  const proseText = makeText('Analyzing the remote architecture.');
  const codeText = makeText('const keepCodeUntouched = true;');
  const preText = makeText('npm run verify');
  const inputText = makeText('Editable draft text');
  const dockText = makeText('Remote Dock Label');
  const dynamicText = makeText('Streaming second thought step.');

  const body = makeNode('body', {
    children: [
      makeNode('p', { children: [proseText] }),
      makeNode('code', { children: [codeText] }),
      makeNode('pre', { children: [preText] }),
      makeNode('div', { attrs: { contenteditable: 'true' }, children: [inputText] }),
      makeNode('div', { attrs: { 'data-remote-dock-ignore': 'true' }, children: [dockText] }),
    ],
  });

  let observerCb = null;
  class FakeMutationObserver {
    constructor(cb) {
      observerCb = cb;
    }
    observe() {
      this.observing = true;
    }
    disconnect() {
      this.observing = false;
    }
  }

  const statuses = [];
  const engine = createRemoteTranslatorEngine({
    win: { MutationObserver: FakeMutationObserver },
    doc: { body, documentElement: body },
    settings: { enabled: true, targetLang: 'ko' },
    async translateText(text) {
      return `[KO] ${text}`;
    },
    onStatus: (s) => statuses.push(s),
  });

  engine.start();
  await new Promise((r) => setTimeout(r, 30));

  assert.equal(proseText.nodeValue, '[KO] Analyzing the remote architecture.');
  assert.equal(codeText.nodeValue, 'const keepCodeUntouched = true;');
  assert.equal(preText.nodeValue, 'npm run verify');
  assert.equal(inputText.nodeValue, 'Editable draft text');
  assert.equal(dockText.nodeValue, 'Remote Dock Label');
  assert.equal(engine.getStats().translatedCount, 1);

  // Dynamic node inserted via MutationObserver must also translate.
  const dynEl = makeNode('div', { children: [dynamicText] });
  dynEl.parentElement = body;
  dynEl.parentNode = body;
  body.childNodes.push(dynEl);
  observerCb([{ type: 'childList', addedNodes: [dynEl] }]);
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(dynamicText.nodeValue, '[KO] Streaming second thought step.');
  assert.equal(engine.getStats().translatedCount, 2);

  // Turning OFF must restore 100% of original text immediately.
  engine.updateSettings({ enabled: false });
  assert.equal(proseText.nodeValue, 'Analyzing the remote architecture.');
  assert.equal(dynamicText.nodeValue, 'Streaming second thought step.');
  assert.equal(engine.getStats().translatedCount, 0);

  // Re-enabling translates again (from cache), and dispose() restores originals cleanly.
  engine.updateSettings({ enabled: true });
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(proseText.nodeValue, '[KO] Analyzing the remote architecture.');
  engine.dispose();
  assert.equal(proseText.nodeValue, 'Analyzing the remote architecture.');
  assert.equal(dynamicText.nodeValue, 'Streaming second thought step.');
  assert.ok(statuses.some((s) => s.phase === 'disposed'));
});
