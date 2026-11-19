import { SecurityPolicyError } from '../security/origin-policy.js';
import { redactUrl } from '../security/redactor.js';

export const REMOTE_PLUGIN_CONTRACT_VERSION = 'remote-plugin.v1';

export const ALLOWED_UI_SLOTS = Object.freeze([
  'title-bar',
  'sidebar',
  'status-bar',
  'composer-toolbar',
  'settings-pane',
  'aux-pane',
  'modal',
  'overlay',
  'theme',
  'custom',
]);

export const ALLOWED_CAPABILITIES = Object.freeze([
  'badge',
  'panel',
  'actions',
  'subscribe',
]);

const ALLOWED_SLOT_SET = new Set(ALLOWED_UI_SLOTS);
const ALLOWED_CAPABILITY_SET = new Set(ALLOWED_CAPABILITIES);
const ALLOWED_TONES = new Set(['neutral', 'info', 'ok', 'warn', 'error']);
const ALLOWED_BUTTON_STYLES = new Set(['primary', 'secondary', 'danger']);
const ALLOWED_ACTION_STATUSES = new Set([
  'ok',
  'confirmation_required',
  'conflict',
  'error',
]);

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const PLUGIN_ID_RE = /^[a-z0-9][a-z0-9._-]{1,63}$/;
const SLOT_ID_RE = /^[a-z0-9][a-z0-9._-]{1,95}$/;
const ACTION_ID_RE = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,63}$/;
const SEMVER_RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const BIDI_CONTROL_RE = /[\u202A-\u202E\u2066-\u2069]/;
const DANGEROUS_URI_RE = /(?:javascript|vbscript|data)\s*:/i;
const RAW_MARKUP_RE = /<\s*(?:script|svg|iframe|object|embed|style|link|base)\b/i;

const MAX_TEXT_LENGTH = 1000;
const MAX_SECTIONS = 24;
const MAX_ITEMS_PER_SECTION = 64;

function isPlainObject(val) {
  if (!val || typeof val !== 'object' || Array.isArray(val)) {
    return false;
  }
  const proto = Object.getPrototypeOf(val);
  return proto === Object.prototype || proto === null;
}

function assertNoForbiddenKeys(obj, label) {
  if (!obj || typeof obj !== 'object') {
    return;
  }
  for (const key of Object.keys(obj)) {
    if (FORBIDDEN_KEYS.has(key)) {
      throw new SecurityPolicyError(
        'ERR_FORBIDDEN_KEY',
        `Forbidden key "${key}" detected in ${label}.`,
      );
    }
  }
}

export function assertSafeText(value, label, { maxLength = MAX_TEXT_LENGTH } = {}) {
  if (typeof value !== 'string') {
    throw new SecurityPolicyError('ERR_INVALID_TEXT', `${label} must be a string.`);
  }
  if (value.length > maxLength) {
    throw new SecurityPolicyError(
      'ERR_TEXT_TOO_LONG',
      `${label} exceeds maximum allowed length (${maxLength}).`,
    );
  }
  if (BIDI_CONTROL_RE.test(value)) {
    throw new SecurityPolicyError(
      'ERR_FORBIDDEN_BIDI_CONTROL',
      `${label} contains forbidden bidirectional override control characters.`,
    );
  }
  const collapsed = value.replace(/[\u0000-\u0020\u007f]+/g, '');
  if (DANGEROUS_URI_RE.test(collapsed)) {
    throw new SecurityPolicyError(
      'ERR_FORBIDDEN_URI_SCHEME',
      `${label} contains a forbidden URI scheme.`,
    );
  }
  if (RAW_MARKUP_RE.test(value)) {
    throw new SecurityPolicyError(
      'ERR_FORBIDDEN_MARKUP',
      `${label} contains forbidden active HTML or SVG markup.`,
    );
  }
  return value;
}

export function assertSafeLocalizedText(value, label) {
  if (typeof value === 'string') {
    return assertSafeText(value, label);
  }
  if (!isPlainObject(value)) {
    throw new SecurityPolicyError(
      'ERR_INVALID_LOCALIZED_TEXT',
      `${label} must be a string or { ko, en } object.`,
    );
  }
  assertNoForbiddenKeys(value, label);
  const hasKo = typeof value.ko === 'string' && value.ko.length > 0;
  const hasEn = typeof value.en === 'string' && value.en.length > 0;
  if (!hasKo && !hasEn) {
    throw new SecurityPolicyError(
      'ERR_EMPTY_LOCALIZED_TEXT',
      `${label} must provide at least one non-empty "ko" or "en" string.`,
    );
  }
  const normalized = Object.create(null);
  if (hasKo) {
    normalized.ko = assertSafeText(value.ko, `${label}.ko`);
  }
  if (hasEn) {
    normalized.en = assertSafeText(value.en, `${label}.en`);
  }
  return Object.freeze(normalized);
}

export function resolveLocalizedText(value, locale = 'ko') {
  if (typeof value === 'string') {
    return value;
  }
  if (!value || typeof value !== 'object') {
    return '';
  }
  if (locale === 'en') {
    return typeof value.en === 'string' ? value.en : typeof value.ko === 'string' ? value.ko : '';
  }
  return typeof value.ko === 'string' ? value.ko : typeof value.en === 'string' ? value.en : '';
}

export function validateRemotePlugin(plugin) {
  if (!plugin || typeof plugin !== 'object' || Array.isArray(plugin)) {
    throw new SecurityPolicyError('ERR_INVALID_PLUGIN', 'RemotePlugin.v1 descriptor must be an object.');
  }
  assertNoForbiddenKeys(plugin, 'plugin');

  if (plugin.contractVersion !== REMOTE_PLUGIN_CONTRACT_VERSION) {
    throw new SecurityPolicyError(
      'ERR_UNSUPPORTED_CONTRACT_VERSION',
      `Plugin contractVersion must be "${REMOTE_PLUGIN_CONTRACT_VERSION}".`,
    );
  }
  if (typeof plugin.mount === 'function') {
    throw new SecurityPolicyError(
      'ERR_IMPERATIVE_MOUNT_FORBIDDEN',
      'RemotePlugin.v1 plugins must be declarative-only and cannot define imperative mount().',
    );
  }
  if (typeof plugin.id !== 'string' || !PLUGIN_ID_RE.test(plugin.id) || FORBIDDEN_KEYS.has(plugin.id)) {
    throw new SecurityPolicyError('ERR_INVALID_PLUGIN_ID', 'Invalid RemotePlugin.v1 id.');
  }
  if (typeof plugin.version !== 'string' || !SEMVER_RE.test(plugin.version)) {
    throw new SecurityPolicyError('ERR_INVALID_PLUGIN_VERSION', 'Plugin version must be valid SemVer.');
  }

  const displayName = assertSafeLocalizedText(plugin.displayName, 'plugin.displayName');

  if (!isPlainObject(plugin.uiSlot)) {
    throw new SecurityPolicyError('ERR_INVALID_UI_SLOT', 'Plugin must declare a uiSlot object.');
  }
  assertNoForbiddenKeys(plugin.uiSlot, 'plugin.uiSlot');
  if (typeof plugin.uiSlot.slot !== 'string' || !ALLOWED_SLOT_SET.has(plugin.uiSlot.slot)) {
    throw new SecurityPolicyError(
      'ERR_UNSUPPORTED_UI_SLOT',
      `Unsupported uiSlot.slot "${String(plugin.uiSlot.slot)}".`,
    );
  }
  if (
    typeof plugin.uiSlot.slotId !== 'string' ||
    !SLOT_ID_RE.test(plugin.uiSlot.slotId) ||
    FORBIDDEN_KEYS.has(plugin.uiSlot.slotId)
  ) {
    throw new SecurityPolicyError('ERR_INVALID_SLOT_ID', 'Invalid uiSlot.slotId.');
  }
  if (plugin.uiSlot.exclusive !== undefined && typeof plugin.uiSlot.exclusive !== 'boolean') {
    throw new SecurityPolicyError(
      'ERR_INVALID_EXCLUSIVE_FLAG',
      'uiSlot.exclusive must be a boolean when provided.',
    );
  }
  const exclusive = plugin.uiSlot.exclusive === true;

  if (!Array.isArray(plugin.capabilities) || plugin.capabilities.length === 0) {
    throw new SecurityPolicyError(
      'ERR_INVALID_CAPABILITIES',
      'Plugin must declare at least one capability.',
    );
  }
  const capabilities = [];
  const seenCaps = new Set();
  for (const cap of plugin.capabilities) {
    if (typeof cap !== 'string' || !ALLOWED_CAPABILITY_SET.has(cap)) {
      throw new SecurityPolicyError(
        'ERR_UNSUPPORTED_CAPABILITY',
        `Unsupported capability "${String(cap)}".`,
      );
    }
    if (!seenCaps.has(cap)) {
      seenCaps.add(cap);
      capabilities.push(cap);
    }
  }

  if (typeof plugin.getSnapshot !== 'function') {
    throw new SecurityPolicyError(
      'ERR_MISSING_GET_SNAPSHOT',
      'RemotePlugin.v1 requires a getSnapshot(ctx) method.',
    );
  }
  if (seenCaps.has('actions') && typeof plugin.invoke !== 'function') {
    throw new SecurityPolicyError(
      'ERR_MISSING_INVOKE',
      'Plugin declaring "actions" capability must implement invoke(actionId, invocation, ctx).',
    );
  }
  if (seenCaps.has('subscribe') && typeof plugin.subscribe !== 'function') {
    throw new SecurityPolicyError(
      'ERR_MISSING_SUBSCRIBE',
      'Plugin declaring "subscribe" capability must implement subscribe(onDirty, ctx).',
    );
  }

  let loadOrder = 100;
  if (plugin.loadOrder !== undefined) {
    if (!Number.isInteger(plugin.loadOrder) || plugin.loadOrder < 0 || plugin.loadOrder > 1000) {
      throw new SecurityPolicyError(
        'ERR_INVALID_LOAD_ORDER',
        'Plugin loadOrder must be an integer between 0 and 1000.',
      );
    }
    loadOrder = plugin.loadOrder;
  }

  return Object.freeze({
    contractVersion: REMOTE_PLUGIN_CONTRACT_VERSION,
    id: plugin.id,
    version: plugin.version,
    displayName,
    uiSlot: Object.freeze({
      slot: plugin.uiSlot.slot,
      slotId: plugin.uiSlot.slotId,
      exclusive,
    }),
    capabilities: Object.freeze(capabilities),
    loadOrder,
    getSnapshot: plugin.getSnapshot.bind(plugin),
    invoke: typeof plugin.invoke === 'function' ? plugin.invoke.bind(plugin) : null,
    subscribe: typeof plugin.subscribe === 'function' ? plugin.subscribe.bind(plugin) : null,
    dispose: typeof plugin.dispose === 'function' ? plugin.dispose.bind(plugin) : null,
  });
}

function validateTone(tone, fallback = 'neutral') {
  if (tone === undefined) {
    return fallback;
  }
  if (typeof tone !== 'string' || !ALLOWED_TONES.has(tone)) {
    throw new SecurityPolicyError('ERR_INVALID_TONE', `Invalid tone "${String(tone)}".`);
  }
  return tone;
}

function validateSection(section, index) {
  const label = `snapshot.sections[${index}]`;
  if (!isPlainObject(section)) {
    throw new SecurityPolicyError('ERR_INVALID_SECTION', `${label} must be a plain object.`);
  }
  assertNoForbiddenKeys(section, label);

  if (section.kind === 'notice') {
    return Object.freeze({
      kind: 'notice',
      text: assertSafeLocalizedText(section.text, `${label}.text`),
      tone: validateTone(section.tone, 'info'),
    });
  }

  if (section.kind === 'metrics') {
    if (!Array.isArray(section.items) || section.items.length > MAX_ITEMS_PER_SECTION) {
      throw new SecurityPolicyError('ERR_INVALID_SECTION_ITEMS', `${label}.items must be a bounded array.`);
    }
    const items = section.items.map((item, i) => {
      if (!isPlainObject(item)) {
        throw new SecurityPolicyError('ERR_INVALID_METRIC', `${label}.items[${i}] must be a plain object.`);
      }
      assertNoForbiddenKeys(item, `${label}.items[${i}]`);
      return Object.freeze({
        label: assertSafeLocalizedText(item.label, `${label}.items[${i}].label`),
        value: assertSafeText(String(item.value ?? ''), `${label}.items[${i}].value`, { maxLength: 160 }),
        tone: validateTone(item.tone, 'neutral'),
      });
    });
    return Object.freeze({ kind: 'metrics', items: Object.freeze(items) });
  }

  if (section.kind === 'list') {
    if (!Array.isArray(section.items) || section.items.length > MAX_ITEMS_PER_SECTION) {
      throw new SecurityPolicyError('ERR_INVALID_SECTION_ITEMS', `${label}.items must be a bounded array.`);
    }
    const title = section.title !== undefined ? assertSafeLocalizedText(section.title, `${label}.title`) : null;
    const items = section.items.map((item, i) => {
      if (!isPlainObject(item)) {
        throw new SecurityPolicyError('ERR_INVALID_LIST_ITEM', `${label}.items[${i}] must be a plain object.`);
      }
      assertNoForbiddenKeys(item, `${label}.items[${i}]`);
      return Object.freeze({
        id: assertSafeText(String(item.id ?? i), `${label}.items[${i}].id`, { maxLength: 128 }),
        primary: assertSafeLocalizedText(item.primary, `${label}.items[${i}].primary`),
        secondary:
          item.secondary !== undefined
            ? assertSafeLocalizedText(item.secondary, `${label}.items[${i}].secondary`)
            : null,
        badge:
          item.badge !== undefined
            ? assertSafeLocalizedText(item.badge, `${label}.items[${i}].badge`)
            : null,
      });
    });
    return Object.freeze({ kind: 'list', title, items: Object.freeze(items) });
  }

  if (section.kind === 'key-value') {
    if (!Array.isArray(section.entries) || section.entries.length > MAX_ITEMS_PER_SECTION) {
      throw new SecurityPolicyError('ERR_INVALID_SECTION_ITEMS', `${label}.entries must be a bounded array.`);
    }
    const title = section.title !== undefined ? assertSafeLocalizedText(section.title, `${label}.title`) : null;
    const entries = section.entries.map((entry, i) => {
      if (!isPlainObject(entry)) {
        throw new SecurityPolicyError('ERR_INVALID_ENTRY', `${label}.entries[${i}] must be a plain object.`);
      }
      assertNoForbiddenKeys(entry, `${label}.entries[${i}]`);
      return Object.freeze({
        key: assertSafeLocalizedText(entry.key, `${label}.entries[${i}].key`),
        value: assertSafeText(String(entry.value ?? ''), `${label}.entries[${i}].value`, { maxLength: 240 }),
      });
    });
    return Object.freeze({ kind: 'key-value', title, entries: Object.freeze(entries) });
  }

  if (section.kind === 'actions') {
    if (!Array.isArray(section.items) || section.items.length > MAX_ITEMS_PER_SECTION) {
      throw new SecurityPolicyError('ERR_INVALID_SECTION_ITEMS', `${label}.items must be a bounded array.`);
    }
    const title = section.title !== undefined ? assertSafeLocalizedText(section.title, `${label}.title`) : null;
    const items = section.items.map((item, i) => {
      if (!isPlainObject(item)) {
        throw new SecurityPolicyError('ERR_INVALID_ACTION_ITEM', `${label}.items[${i}] must be a plain object.`);
      }
      assertNoForbiddenKeys(item, `${label}.items[${i}]`);
      if (typeof item.id !== 'string' || !ACTION_ID_RE.test(item.id)) {
        throw new SecurityPolicyError('ERR_INVALID_ACTION_ID', `Invalid action id in ${label}.items[${i}].`);
      }
      const style = item.style === undefined ? 'secondary' : item.style;
      if (typeof style !== 'string' || !ALLOWED_BUTTON_STYLES.has(style)) {
        throw new SecurityPolicyError('ERR_INVALID_BUTTON_STYLE', `Invalid action style "${String(style)}".`);
      }
      return Object.freeze({
        id: item.id,
        label: assertSafeLocalizedText(item.label, `${label}.items[${i}].label`),
        style,
        disabled: Boolean(item.disabled),
      });
    });
    return Object.freeze({ kind: 'actions', title, items: Object.freeze(items) });
  }

  throw new SecurityPolicyError(
    'ERR_UNSUPPORTED_SECTION_KIND',
    `Unsupported declarative section kind "${String(section.kind)}".`,
  );
}

export function validatePluginSnapshot(snapshot) {
  if (!isPlainObject(snapshot)) {
    throw new SecurityPolicyError('ERR_INVALID_SNAPSHOT', 'Plugin snapshot must be a plain object.');
  }
  assertNoForbiddenKeys(snapshot, 'snapshot');

  const revision =
    snapshot.revision !== undefined && snapshot.revision !== null
      ? assertSafeText(String(snapshot.revision), 'snapshot.revision', { maxLength: 128 })
      : null;

  let badge = null;
  if (snapshot.badge !== undefined && snapshot.badge !== null) {
    if (!isPlainObject(snapshot.badge)) {
      throw new SecurityPolicyError('ERR_INVALID_BADGE', 'snapshot.badge must be a plain object.');
    }
    assertNoForbiddenKeys(snapshot.badge, 'snapshot.badge');
    badge = Object.freeze({
      text: assertSafeLocalizedText(snapshot.badge.text, 'snapshot.badge.text'),
      tone: validateTone(snapshot.badge.tone, 'neutral'),
    });
  }

  let notice = null;
  if (snapshot.notice !== undefined && snapshot.notice !== null) {
    if (!isPlainObject(snapshot.notice)) {
      throw new SecurityPolicyError('ERR_INVALID_NOTICE', 'snapshot.notice must be a plain object.');
    }
    assertNoForbiddenKeys(snapshot.notice, 'snapshot.notice');
    notice = Object.freeze({
      text: assertSafeLocalizedText(snapshot.notice.text, 'snapshot.notice.text'),
      tone: validateTone(snapshot.notice.tone, 'info'),
    });
  }

  const rawSections = snapshot.sections === undefined ? [] : snapshot.sections;
  if (!Array.isArray(rawSections) || rawSections.length > MAX_SECTIONS) {
    throw new SecurityPolicyError(
      'ERR_INVALID_SECTIONS',
      `snapshot.sections must be an array with at most ${MAX_SECTIONS} items.`,
    );
  }
  const sections = Object.freeze(rawSections.map((sec, idx) => validateSection(sec, idx)));

  return Object.freeze({
    revision,
    badge,
    notice,
    sections,
  });
}

export function validateActionInvocation(actionId, invocation = {}) {
  if (typeof actionId !== 'string' || !ACTION_ID_RE.test(actionId)) {
    throw new SecurityPolicyError('ERR_INVALID_ACTION_ID', 'Invalid actionId.');
  }
  if (!isPlainObject(invocation)) {
    throw new SecurityPolicyError('ERR_INVALID_INVOCATION', 'Action invocation must be a plain object.');
  }
  assertNoForbiddenKeys(invocation, 'invocation');

  const clean = Object.create(null);
  if (invocation.expectedRevision !== undefined && invocation.expectedRevision !== null) {
    clean.expectedRevision = assertSafeText(String(invocation.expectedRevision), 'invocation.expectedRevision', {
      maxLength: 128,
    });
  }
  if (invocation.params !== undefined && invocation.params !== null) {
    if (!isPlainObject(invocation.params)) {
      throw new SecurityPolicyError('ERR_INVALID_PARAMS', 'invocation.params must be a plain object.');
    }
    assertNoForbiddenKeys(invocation.params, 'invocation.params');
    const safeParams = Object.create(null);
    for (const [k, v] of Object.entries(invocation.params)) {
      if (typeof v === 'string') {
        safeParams[k] = assertSafeText(v, `invocation.params.${k}`);
      } else if (typeof v === 'number' && Number.isFinite(v)) {
        safeParams[k] = v;
      } else if (typeof v === 'boolean') {
        safeParams[k] = v;
      } else {
        throw new SecurityPolicyError(
          'ERR_INVALID_PARAM_VALUE',
          `invocation.params.${k} must be a primitive string, finite number, or boolean.`,
        );
      }
    }
    clean.params = Object.freeze(safeParams);
  }
  if (invocation.challengeResponse !== undefined && invocation.challengeResponse !== null) {
    if (!isPlainObject(invocation.challengeResponse)) {
      throw new SecurityPolicyError(
        'ERR_INVALID_CHALLENGE_RESPONSE',
        'invocation.challengeResponse must be a plain object.',
      );
    }
    assertNoForbiddenKeys(invocation.challengeResponse, 'invocation.challengeResponse');
    const challengeId = assertSafeText(
      String(invocation.challengeResponse.challengeId ?? ''),
      'invocation.challengeResponse.challengeId',
      { maxLength: 128 },
    );
    if (!challengeId) {
      throw new SecurityPolicyError('ERR_INVALID_CHALLENGE_ID', 'challengeId must be non-empty.');
    }
    if (typeof invocation.challengeResponse.confirmed !== 'boolean') {
      throw new SecurityPolicyError(
        'ERR_INVALID_CHALLENGE_CONFIRMED',
        'challengeResponse.confirmed must be a boolean.',
      );
    }
    clean.challengeResponse = Object.freeze({
      challengeId,
      confirmed: invocation.challengeResponse.confirmed,
    });
  }
  return Object.freeze(clean);
}

function redactLocalizedMessage(value, label) {
  const validated = assertSafeLocalizedText(value, label);
  if (typeof validated === 'string') {
    return redactUrl(validated);
  }
  const out = Object.create(null);
  if (validated.ko) {
    out.ko = redactUrl(validated.ko);
  }
  if (validated.en) {
    out.en = redactUrl(validated.en);
  }
  return Object.freeze(out);
}

export function validateActionResult(result) {
  if (!isPlainObject(result)) {
    throw new SecurityPolicyError('ERR_INVALID_ACTION_RESULT', 'ActionResult.v1 must be a plain object.');
  }
  assertNoForbiddenKeys(result, 'actionResult');

  if (typeof result.status !== 'string' || !ALLOWED_ACTION_STATUSES.has(result.status)) {
    throw new SecurityPolicyError(
      'ERR_INVALID_ACTION_STATUS',
      `Invalid ActionResult status "${String(result.status)}".`,
    );
  }

  if (result.status === 'confirmation_required') {
    const challengeId = assertSafeText(String(result.challengeId ?? ''), 'actionResult.challengeId', {
      maxLength: 128,
    });
    if (!challengeId) {
      throw new SecurityPolicyError(
        'ERR_MISSING_CHALLENGE_ID',
        'confirmation_required result must include a non-empty challengeId.',
      );
    }
    const message = redactLocalizedMessage(result.message, 'actionResult.message');
    const confirmLabel =
      result.confirmLabel !== undefined
        ? assertSafeLocalizedText(result.confirmLabel, 'actionResult.confirmLabel')
        : null;
    return Object.freeze({
      status: 'confirmation_required',
      challengeId,
      message,
      confirmLabel,
    });
  }

  if (result.status === 'conflict') {
    const message = redactLocalizedMessage(
      result.message ?? { ko: '상태가 변경되었습니다. 새로고침 후 다시 시도하세요.', en: 'State changed. Refresh and retry.' },
      'actionResult.message',
    );
    const currentRevision =
      result.currentRevision !== undefined && result.currentRevision !== null
        ? assertSafeText(String(result.currentRevision), 'actionResult.currentRevision', { maxLength: 128 })
        : null;
    return Object.freeze({
      status: 'conflict',
      message,
      currentRevision,
    });
  }

  if (result.status === 'error') {
    const message = redactLocalizedMessage(
      result.message ?? { ko: '작업을 완료하지 못했습니다.', en: 'Action failed.' },
      'actionResult.message',
    );
    return Object.freeze({
      status: 'error',
      message,
    });
  }

  const message =
    result.message !== undefined && result.message !== null
      ? redactLocalizedMessage(result.message, 'actionResult.message')
      : null;
  const revision =
    result.revision !== undefined && result.revision !== null
      ? assertSafeText(String(result.revision), 'actionResult.revision', { maxLength: 128 })
      : null;
  return Object.freeze({
    status: 'ok',
    message,
    revision,
  });
}
