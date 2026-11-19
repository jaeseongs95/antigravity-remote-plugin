import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));

test('ARP-TC-019 & ARP-TC-024: esbuild-backed scripts/build.js generates deterministic standalone bundle & verified 18-module manifest', async () => {
  const outDirA = mkdtempSync(join(tmpdir(), 'arp-build-a-'));
  const outDirB = mkdtempSync(join(tmpdir(), 'arp-build-b-'));
  const isolatedDir = mkdtempSync(join(tmpdir(), 'arp-standalone-'));

  try {
    execFileSync(process.execPath, [join(ROOT, 'scripts/build.js'), '--out-dir', outDirA], { cwd: ROOT });
    execFileSync(process.execPath, [join(ROOT, 'scripts/build.js'), '--out-dir', outDirB], { cwd: ROOT });

    const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
    const pluginJson = JSON.parse(readFileSync(join(ROOT, 'plugin.json'), 'utf8'));
    const manifest = JSON.parse(readFileSync(join(outDirA, 'manifest.json'), 'utf8'));
    const bundle = readFileSync(join(outDirA, 'remote_bridge.js'), 'utf8');
    const secondBundle = readFileSync(join(outDirB, 'remote_bridge.js'), 'utf8');
    const committedBundle = readFileSync(join(ROOT, 'dist/remote_bridge.js'), 'utf8');
    const committedManifest = JSON.parse(readFileSync(join(ROOT, 'dist/manifest.json'), 'utf8'));

    assert.equal(pkg.version, '1.1.0');
    assert.equal(pluginJson.version, pkg.version);
    assert.equal(manifest.version, pkg.version);
    assert.equal(manifest.bundler, 'esbuild');
    assert.equal(manifest.moduleCount, 18);
    assert.equal(manifest.modules.length, 18);

    // Verify byte-for-byte determinism across isolated builds and committed dist/.
    assert.equal(secondBundle, bundle, 'esbuild output must be byte-for-byte deterministic');
    assert.equal(committedBundle.replace(/\r\n/g, '\n'), bundle, 'dist/remote_bridge.js must match fresh esbuild output');
    assert.equal(committedManifest.entrySha256, manifest.entrySha256);

    // Verify bundle checksum and every single module SHA-256 against disk.
    const actualBundleSha = createHash('sha256').update(bundle, 'utf8').digest('hex');
    assert.equal(manifest.entrySha256, actualBundleSha);

    for (const mod of manifest.modules) {
      const srcContent = readFileSync(join(ROOT, mod.path), 'utf8').replace(/\r\n/g, '\n');
      const actualModSha = createHash('sha256').update(srcContent, 'utf8').digest('hex');
      assert.equal(mod.sha256, actualModSha, `SHA-256 mismatch for ${mod.path}`);
    }

    // Must be self-contained: zero relative ../src/ imports and zero legacy markers.
    assert.ok(!/from\s+['"]\.\.?\/src\//.test(bundle));
    assert.ok(!/statusbar_autoinject/i.test(bundle));
    assert.ok(!/app\.asar/i.test(bundle));

    // Verify standalone execution by copying ONLY remote_bridge.js into an isolated temp dir.
    const copiedBundle = join(isolatedDir, 'remote_bridge.mjs');
    copyFileSync(join(outDirA, 'remote_bridge.js'), copiedBundle);
    const loaded = await import(pathToFileURL(copiedBundle).href);
    assert.equal(loaded.BUILD_VERSION, '1.1.0');
    assert.equal(typeof loaded.bootstrapAntigravityRemoteBridge, 'function');
    assert.equal(typeof loaded.RemoteOrchestrator, 'function');
  } finally {
    rmSync(outDirA, { recursive: true, force: true });
    rmSync(outDirB, { recursive: true, force: true });
    rmSync(isolatedDir, { recursive: true, force: true });
  }
});
