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

test('ARP-TC-001: core, security, and bridges contain zero vendor literals', () => {
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
  ];
  // Exception: trusted-types.js explicitly lists 'angular' in RESERVED_TRUSTED_TYPES_POLICIES
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
  assert.deepEqual(violations, []);
});

test('ARP-TC-002: core and security contain zero HTML sink calls or assignments', () => {
  const sinkPatterns = [
    /\.innerHTML\b/,
    /\.outerHTML\b/,
    /insertAdjacentHTML\s*\(/,
    /document\.write\s*\(/,
  ];
  const dirs = ['src/core', 'src/security'];
  const violations = [];

  for (const relDir of dirs) {
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

test('ARP-TC-003: entire src/ contains zero forbidden legacy patterns or empty catch blocks', () => {
  const forbidden = [
    /app\.asar/i,
    /statusbar_autoinject/i,
    /agy-statusbar-code/i,
    /window\.agyMcpManager/,
    /catch\s*\{\s*\}/,
  ];
  const violations = [];
  for (const file of collectJsFiles(join(ROOT, 'src'))) {
    const content = readFileSync(file, 'utf8');
    for (const pattern of forbidden) {
      if (pattern.test(content)) {
        violations.push(`${file} matched ${pattern}`);
      }
    }
  }
  assert.deepEqual(violations, []);
});
