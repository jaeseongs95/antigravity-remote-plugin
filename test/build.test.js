import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));

test('ARP-TC-019: scripts/build.js generates deterministic bundle & manifest matching version', () => {
  execFileSync(process.execPath, [join(ROOT, 'scripts/build.js')], { cwd: ROOT });

  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  const pluginJson = JSON.parse(readFileSync(join(ROOT, 'plugin.json'), 'utf8'));
  const manifest = JSON.parse(readFileSync(join(ROOT, 'dist/manifest.json'), 'utf8'));
  const bundle = readFileSync(join(ROOT, 'dist/remote_bridge.js'), 'utf8');

  assert.equal(pkg.version, '0.1.0');
  assert.equal(pluginJson.version, pkg.version);
  assert.equal(manifest.version, pkg.version);

  const actualSha = createHash('sha256').update(bundle, 'utf8').digest('hex');
  assert.equal(manifest.entrySha256, actualSha);
  assert.equal(manifest.moduleCount, manifest.modules.length);
  assert.ok(!/statusbar_autoinject/i.test(bundle));
  assert.ok(!/app\.asar/i.test(bundle));
});
