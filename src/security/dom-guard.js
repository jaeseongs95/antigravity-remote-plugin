import { SecurityPolicyError } from './origin-policy.js';

const FORBIDDEN_TAGS = new Set(['base', 'script', 'object', 'embed']);

const FORBIDDEN_PROP_PREFIXES = Object.freeze([
  'on',
]);

const FORBIDDEN_HTML_PROPS = new Set([
  ['inner', 'HTML'].join(''),
  ['outer', 'HTML'].join(''),
  ['insertAdjacent', 'HTML'].join(''),
  'srcdoc',
]);

export function assertSafeTagName(tagName) {
  if (typeof tagName !== 'string' || tagName.trim().length === 0) {
    throw new SecurityPolicyError('INVALID_TAG_NAME', 'Tag name must be a non-empty string.');
  }
  const normalized = tagName.trim().toLowerCase();
  if (FORBIDDEN_TAGS.has(normalized)) {
    throw new SecurityPolicyError(
      'FORBIDDEN_ELEMENT_TAG',
      `Creating <${normalized}> elements is forbidden by security policy.`,
    );
  }
  return normalized;
}

export function assertSafeAttribute(attrName, attrValue) {
  if (typeof attrName !== 'string' || attrName.trim().length === 0) {
    throw new SecurityPolicyError('INVALID_ATTRIBUTE', 'Attribute name must be non-empty.');
  }
  const normalized = attrName.trim();
  const lower = normalized.toLowerCase();
  if (FORBIDDEN_HTML_PROPS.has(normalized) || FORBIDDEN_HTML_PROPS.has(lower)) {
    throw new SecurityPolicyError(
      'FORBIDDEN_HTML_SINK',
      `Setting unsafe HTML sink "${attrName}" is forbidden.`,
    );
  }
  for (const prefix of FORBIDDEN_PROP_PREFIXES) {
    if (lower.startsWith(prefix) && lower.length > prefix.length) {
      throw new SecurityPolicyError(
        'FORBIDDEN_EVENT_ATTRIBUTE',
        `Inline event handler attribute "${attrName}" is forbidden.`,
      );
    }
  }
  if (typeof attrValue === 'string' && /^\s*javascript:/i.test(attrValue)) {
    throw new SecurityPolicyError(
      'FORBIDDEN_JAVASCRIPT_URI',
      `javascript: URI in attribute "${attrName}" is forbidden.`,
    );
  }
}

export function createSafeElement(doc, tagName, { attrs = {}, text = null } = {}) {
  const safeTag = assertSafeTagName(tagName);
  if (!doc || typeof doc.createElement !== 'function') {
    throw new SecurityPolicyError('INVALID_DOCUMENT', 'A document with createElement is required.');
  }
  const el = doc.createElement(safeTag);
  for (const [key, val] of Object.entries(attrs)) {
    assertSafeAttribute(key, val);
    if (val !== null && val !== undefined) {
      el.setAttribute(key, String(val));
    }
  }
  if (text !== null && text !== undefined) {
    el.textContent = String(text);
  }
  return el;
}
