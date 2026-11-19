import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));

function collectJsFiles(dir) {
  const files = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      files.push(...collectJsFiles(full));
    } else if (entry.endsWith('.js') || entry.endsWith('.mjs')) {
      files.push(full);
    }
  }
  return files;
}

test('ARP-TC-001: core, security, and bridges contain zero vendor literals or domain leakage', () => {
  const forbidden = [
    /\bantigravity\b/i,
    /\bgoogle\b/i,
    /\bcodeium\b/i,
    /\bangular\b/i,
    /\belectron\b/i,
    /boq-jetski/i,
    /app\.asar/i,
    /statusbar_autoinject/i,
    /\.gemini\b/i,
    /translateThinking/,
    /translateStaticUi/,
    /local-llm/,
  ];
  const dirs = ['src/core', 'src/security', 'src/bridges'];
  const violations = [];

  for (const relDir of dirs) {
    for (const file of collectJsFiles(join(ROOT, relDir))) {
      const content = readFileSync(file, 'utf8');
      for (const pattern of forbidden) {
        if (file.endsWith('trusted-types.js') && pattern.source === '\\bangular\\b') {
          continue;
        }
        if (pattern.test(content)) {
          violations.push(`${file} matched ${pattern}`);
        }
      }
    }
  }

  // Hexagonal boundary: adapters must not import from bridges.
  for (const file of collectJsFiles(join(ROOT, 'src/adapters'))) {
    const content = readFileSync(file, 'utf8');
    if (/from\s+['"][^'"]*bridges\//.test(content)) {
      violations.push(`${file} reverse-imports from bridges/`);
    }
  }

  assert.deepEqual(violations, []);
});

test('ARP-TC-002: entire src/ and sidecars/ contain zero HTML sink calls or assignments', () => {
  const sinkPatterns = [
    /\.innerHTML\b/,
    /\.outerHTML\b/,
    /insertAdjacentHTML\s*\(/,
    /document\.write\s*\(/,
  ];
  const violations = [];

  for (const relDir of ['src', 'sidecars']) {
    for (const file of collectJsFiles(join(ROOT, relDir))) {
      const content = readFileSync(file, 'utf8');
      for (const pattern of sinkPatterns) {
        if (pattern.test(content)) {
          violations.push(`${file} matched ${pattern}`);
        }
      }
    }
  }
  assert.deepEqual(violations, []);
});

test('ARP-TC-003: entire src/ and sidecars/ contain zero forbidden legacy patterns or empty catch blocks', () => {
  const forbidden = [
    /app\.asar/i,
    /statusbar_autoinject/i,
    /agy-statusbar-code/i,
    /window\.agyMcpManager/,
    /catch\s*(?:\([^)]*\))?\s*\{\s*\}/,
  ];
  const violations = [];
  for (const relDir of ['src', 'sidecars']) {
    for (const file of collectJsFiles(join(ROOT, relDir))) {
      const content = readFileSync(file, 'utf8');
      for (const pattern of forbidden) {
        if (pattern.test(content)) {
          violations.push(`${file} matched ${pattern}`);
        }
      }
    }
  }
  assert.deepEqual(violations, []);
});
