import test from 'node:test';
import assert from 'node:assert/strict';
import { formatHostForUrl, isOriginAllowed, SecurityPolicyError } from '../src/security/origin-policy.js';
import { createScopedTrustedTypesPolicy } from '../src/security/trusted-types.js';
import {
  createGuardedWorkerBlobUrl,
  isTrustedScriptUrl,
  isTrustedWorkerOrScriptUrl,
} from '../src/security/script-guard.js';
import { assertSafeAttribute, assertSafeTagName, createSafeElement } from '../src/security/dom-guard.js';
import { deepFreeze, REDACTED, redactSecrets, redactUrl, stripSensitiveDeep } from '../src/security/redactor.js';

test('ARP-TC-004: isOriginAllowed enforces exact origin, subdomain & IPv6 loopback boundaries', () => {
  const allowlist = [
    'https://example.com',
    'https://*.example.com',
    'http://127.0.0.1:*',
    'http://[::1]:*',
  ];

  assert.equal(isOriginAllowed('https://example.com', allowlist), true);
  assert.equal(isOriginAllowed('https://app.example.com', allowlist), true);
  assert.equal(isOriginAllowed('http://127.0.0.1:8765', allowlist), true);
  assert.equal(isOriginAllowed('http://[::1]:8765', allowlist), true);
  assert.equal(formatHostForUrl('::1'), '[::1]');

  assert.equal(isOriginAllowed('https://evil-example.com', allowlist), false);
  assert.equal(isOriginAllowed('https://example.com.attacker.test', allowlist), false);
  assert.equal(isOriginAllowed('http://example.com', allowlist), false);
  assert.equal(isOriginAllowed('javascript:alert(1)', allowlist), false);
});

test('ARP-TC-005: createScopedTrustedTypesPolicy blocks reserved names and reuses cached policy on re-init', () => {
  const validator = (url) => isTrustedScriptUrl(url, ['https://example.com']);

  for (const reserved of ['default', 'Default', 'dompurify', 'angular']) {
    assert.throws(
      () => createScopedTrustedTypesPolicy({ policyName: reserved, validateScriptUrl: validator }),
      (err) => err instanceof SecurityPolicyError && err.code === 'RESERVED_TRUSTED_TYPES_POLICY',
    );
  }

  let createCalls = 0;
  const fakeApi = {
    createPolicy(name, rules) {
      createCalls += 1;
      if (createCalls > 1) {
        throw new TypeError(`Policy ${name} already exists`);
      }
      return rules;
    },
  };
  const policy1 = createScopedTrustedTypesPolicy({
    trustedTypesApi: fakeApi,
    policyName: 'remote-bridge-script-v1',
    validateScriptUrl: validator,
  });
  const policy2 = createScopedTrustedTypesPolicy({
    trustedTypesApi: fakeApi,
    policyName: 'remote-bridge-script-v1',
    validateScriptUrl: validator,
  });

  assert.equal(createCalls, 1);
  assert.equal(policy1.createScriptURL('https://example.com/worker.js'), 'https://example.com/worker.js');
  assert.equal(policy2.createScriptURL('https://example.com/worker.js'), 'https://example.com/worker.js');
  assert.throws(
    () => policy1.createScriptURL('https://attacker.test/worker.js'),
    (err) => err instanceof SecurityPolicyError && err.code === 'UNTRUSTED_SCRIPT_URL',
  );
});

test('ARP-TC-006: createGuardedWorkerBlobUrl validates script URL and wraps resulting blob: URL as TrustedScriptURL', () => {
  const allowlist = ['https://example.com'];
  let blobCreated = false;
  const createBlobUrl = () => {
    blobCreated = true;
    return 'blob:https://example.com/uuid-1234';
  };

  for (const bad of ['javascript:alert(1)', 'data:text/javascript,1', 'https://evil-example.com/a.js']) {
    assert.throws(
      () => createGuardedWorkerBlobUrl({ scriptUrl: bad, allowlist, createBlobUrl }),
      (err) => err instanceof SecurityPolicyError && err.code === 'UNTRUSTED_SCRIPT_URL',
    );
  }
  assert.equal(blobCreated, false);

  class FakeTrustedScriptURL {
    constructor(v) { this.value = v; }
    toString() { return this.value; }
  }
  const fakePolicy = createScopedTrustedTypesPolicy({
    trustedTypesApi: {
      createPolicy(_name, rules) {
        return {
          createScriptURL(url) {
            return new FakeTrustedScriptURL(rules.createScriptURL(url));
          },
        };
      },
    },
    policyName: 'worker-blob-test-v1',
    validateScriptUrl: (url) => isTrustedWorkerOrScriptUrl(url, allowlist),
  });

  const wrapped = createGuardedWorkerBlobUrl({
    scriptUrl: 'https://example.com/audio-worklet.js',
    allowlist,
    createBlobUrl,
    trustedTypesPolicy: fakePolicy,
  });
  assert.ok(wrapped instanceof FakeTrustedScriptURL);
  assert.equal(String(wrapped), 'blob:https://example.com/uuid-1234');
});

test('ARP-TC-007: dom-guard blocks <base>, HTML sinks, control-char bypasses, and non-string toString() bypasses', () => {
  assert.throws(
    () => assertSafeTagName('base'),
    (err) => err instanceof SecurityPolicyError && err.code === 'FORBIDDEN_ELEMENT_TAG',
  );
  assert.throws(
    () => assertSafeAttribute('innerHTML', '<b>x</b>'),
    (err) => err instanceof SecurityPolicyError && err.code === 'FORBIDDEN_HTML_SINK',
  );
  assert.throws(
    () => assertSafeAttribute('onclick', 'alert(1)'),
    (err) => err instanceof SecurityPolicyError && err.code === 'FORBIDDEN_EVENT_ATTRIBUTE',
  );

  const bypasses = [
    'java\tscript:alert(1)',
    'java\nscript:alert(1)',
    'vbscript:msgbox(1)',
    'data:text/html,<svg>',
    { toString: () => 'javascript:alert(1)' },
  ];
  for (const bypass of bypasses) {
    assert.throws(
      () => assertSafeAttribute('href', bypass),
      (err) => err instanceof SecurityPolicyError && err.code === 'FORBIDDEN_URI_SCHEME',
    );
  }

  const attrs = new Map();
  const fakeDoc = {
    createElement(tag) {
      return {
        tagName: tag.toUpperCase(),
        textContent: '',
        setAttribute(k, v) { attrs.set(k, v); },
      };
    },
  };
  assert.throws(
    () => createSafeElement(fakeDoc, 'a', { attrs: { href: { toString: () => 'javascript:alert(1)' } } }),
    (err) => err instanceof SecurityPolicyError && err.code === 'FORBIDDEN_URI_SCHEME',
  );

  const el = createSafeElement(fakeDoc, 'div', { attrs: { 'data-role': 'panel' }, text: 'hello' });
  assert.equal(el.tagName, 'DIV');
  assert.equal(el.textContent, 'hello');
  assert.equal(attrs.get('data-role'), 'panel');
});

test('ARP-TC-008: redactSecrets masks query, #token fragment, password, x-sidecar-token, and deepFreeze works', () => {
  const input = {
    url: 'http://user:pw123@127.0.0.1:8765/?conversationId=abc&x-sidecar-token=s1#token=frag-secret',
    headers: { Authorization: 'Bearer xyz', 'X-Sidecar-Token': 'abc' },
    env: { API_KEY: 'top-secret' },
    password: 'my-password',
    csrf_token: 'real-csrf',
    safeField: 'visible',
  };
  const out = deepFreeze(redactSecrets(input));
  assert.equal(out.headers, REDACTED);
  assert.equal(out.env, REDACTED);
  assert.equal(out.password, REDACTED);
  assert.equal(out.csrf_token, REDACTED);
  assert.equal(out.safeField, 'visible');
  assert.ok(!out.url.includes('pw123'));
  assert.ok(!out.url.includes('s1'));
  assert.ok(!out.url.includes('frag-secret'));
  assert.ok(redactUrl(input.url).includes('conversationId=abc'));
  assert.equal(Object.isFrozen(out), true);

  // stripSensitiveDeep: 2D arrays, function elements, and shared non-cyclic DAG refs.
  const shared = { label: 'shared-ok', token: 'drop-me' };
  const cleaned = stripSensitiveDeep({
    refA: shared,
    refB: shared,
    matrix: [[{ secret: 'x', ok: 1 }, () => 'fn']],
  });
  assert.equal(cleaned.refA.label, 'shared-ok');
  assert.equal(cleaned.refB.label, 'shared-ok');
  assert.equal('token' in cleaned.refA, false);
  assert.equal(cleaned.matrix[0].length, 1);
  assert.equal(cleaned.matrix[0][0].ok, 1);
  assert.equal('secret' in cleaned.matrix[0][0], false);
});
