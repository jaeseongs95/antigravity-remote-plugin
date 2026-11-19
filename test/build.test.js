import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));

function sha256(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function readLf(path) {
  return readFileSync(path, 'utf8').replace(/\r\n/g, '\n');
}

test('ARP-TC-019 & ARP-TC-024: esbuild emits deterministic 4-artifact build matching committed dist/ byte-for-byte with zero prod test hooks and side-effect-free ESM import', async () => {
  const outDirA = mkdtempSync(join(tmpdir(), 'arp-build-a-'));
  const outDirB = mkdtempSync(join(tmpdir(), 'arp-build-b-'));
  const isolatedDir = mkdtempSync(join(tmpdir(), 'arp-standalone-'));

  try {
    execFileSync(process.execPath, [join(ROOT, 'scripts/build.js'), '--out-dir', outDirA], { cwd: ROOT });
    execFileSync(process.execPath, [join(ROOT, 'scripts/build.js'), '--out-dir', outDirB], { cwd: ROOT });

    const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
    const pluginJson = JSON.parse(readFileSync(join(ROOT, 'plugin.json'), 'utf8'));
    const addonManifest = JSON.parse(readFileSync(join(ROOT, 'addon-manifest.json'), 'utf8'));
    const manifestA = JSON.parse(readLf(join(outDirA, 'manifest.json')));

    assert.equal(pkg.version, '2.0.0');
    assert.equal(pluginJson.version, pkg.version);
    assert.equal(addonManifest.version, pkg.version);
    assert.equal(manifestA.version, pkg.version);
    assert.equal(manifestA.bundler, 'esbuild');
    assert.equal(manifestA.moduleCount, 28);
    assert.equal(manifestA.modules.length, 28);

    const files = [
      'remote_bridge.js',
      'addon-renderer.js',
      'antigravity-remote.user.js',
      'bookmarklet.txt',
      'manifest.json',
    ];

    for (const fileName of files) {
      const builtA = readLf(join(outDirA, fileName));
      const builtB = readLf(join(outDirB, fileName));
      const committed = readLf(join(ROOT, 'dist', fileName));
      assert.equal(builtB, builtA, `${fileName} must be deterministic across builds`);
      assert.equal(committed, builtA, `committed dist/${fileName} must match fresh rebuild byte-for-byte`);
      assert.equal(sha256(committed), sha256(builtA), `SHA-256 mismatch on dist/${fileName}`);
    }

    const bundle = readLf(join(outDirA, 'remote_bridge.js'));
    const addonRenderer = readLf(join(outDirA, 'addon-renderer.js'));
    const userscript = readLf(join(outDirA, 'antigravity-remote.user.js'));
    const bookmarklet = readLf(join(outDirA, 'bookmarklet.txt'));

    // Verify all 4 artifact SHA-256 digests + addon-manifest.json digest.
    assert.equal(manifestA.entrySha256, sha256(bundle));
    assert.equal(manifestA.artifacts.esm.sha256, sha256(bundle));
    assert.equal(manifestA.artifacts.addonRenderer.sha256, sha256(addonRenderer));
    assert.equal(manifestA.artifacts.userscript.sha256, sha256(userscript));
    assert.equal(manifestA.artifacts.bookmarklet.sha256, sha256(bookmarklet));
    assert.equal(manifestA.addonManifestSha256, sha256(readLf(join(ROOT, 'addon-manifest.json'))));

    // Verify Userscript metadata block & Bookmarklet prefix.
    assert.ok(userscript.startsWith('// ==UserScript==\n'));
    assert.ok(userscript.includes('@match        https://antigravity.google.com/*'));
    assert.ok(userscript.includes('@grant        none'));
    assert.ok(bookmarklet.startsWith('javascript:'));
    assert.ok(!bookmarklet.trim().includes('\n'), 'bookmarklet must be single-line');

    // Verify zero forbidden legacy patterns or production test hooks in all bundles.
    for (const [label, text] of [
      ['remote_bridge.js', bundle],
      ['addon-renderer.js', addonRenderer],
      ['antigravity-remote.user.js', userscript],
      ['bookmarklet.txt', bookmarklet],
    ]) {
      assert.ok(!/__ARP_ALLOWED_ORIGINS__/.test(text), `${label} leaked __ARP_ALLOWED_ORIGINS__`);
      assert.ok(!/__ARP_TRANSLATE_ENDPOINT__/.test(text), `${label} leaked __ARP_TRANSLATE_ENDPOINT__`);
      assert.ok(!/__agyCreateKoTranslator/.test(text), `${label} leaked __agyCreateKoTranslator`);
      assert.ok(!/statusbar_autoinject/i.test(text), `${label} leaked statusbar_autoinject`);
      assert.ok(!/app\.asar/i.test(text), `${label} leaked app.asar`);
    }

    for (const mod of manifestA.modules) {
      const srcContent = readLf(join(ROOT, mod.path));
      assert.equal(mod.sha256, sha256(srcContent), `SHA-256 mismatch for ${mod.path}`);
    }

    assert.ok(!/from\s+['"]\.\.?\/src\//.test(bundle));

    // Verify standalone side-effect-free ESM execution in isolated temp dir.
    const copiedBundle = join(isolatedDir, 'remote_bridge.mjs');
    copyFileSync(join(outDirA, 'remote_bridge.js'), copiedBundle);
    const loaded = await import(pathToFileURL(copiedBundle).href);
    assert.equal(loaded.BUILD_VERSION, '2.0.0');
    assert.equal(typeof loaded.bootstrapAntigravityRemoteBridge, 'function');
    assert.equal(typeof loaded.mountRemotePluginHost, 'function');
    assert.equal(typeof loaded.mountDesktopAddon, 'function');
    assert.equal(typeof loaded.RemotePluginRegistry, 'function');
    assert.equal(typeof loaded.createDeclarativeSlotRenderer, 'function');
  } finally {
    rmSync(outDirA, { recursive: true, force: true });
    rmSync(outDirB, { recursive: true, force: true });
    rmSync(isolatedDir, { recursive: true, force: true });
  }
});
