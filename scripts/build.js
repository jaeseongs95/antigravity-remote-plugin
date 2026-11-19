import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build as esbuild } from 'esbuild';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');

const LIBRARY_SOURCE_FILES = [
  'src/security/redactor.js',
  'src/security/origin-policy.js',
  'src/security/trusted-types.js',
  'src/security/script-guard.js',
  'src/security/dom-guard.js',
  'src/security/plugin-handshake.js',
  'src/core/diagnostics.js',
  'src/core/lifecycle.js',
  'src/core/ports.js',
  'src/core/orchestrator.js',
  'src/core/remote-plugin-contract.js',
  'src/core/remote-plugin-registry.js',
  'src/core/declarative-slot-renderer.js',
  'src/core/desktop-companion-view.js',
  'src/bridges/dom-overlay-bridge.js',
  'src/bridges/sidecar-ui-bridge.js',
  'src/bridges/mcp-extension-slot.js',
  'src/adapters/addon-host/addon-host-surface-adapter.js',
  'src/adapters/remote-web/shadow-surface-adapter.js',
  'src/adapters/antigravity/discovery-adapter.js',
  'src/adapters/antigravity/frame-adapter.js',
  'src/adapters/antigravity/sidecar-adapter.js',
  'src/adapters/antigravity/settings-adapter.js',
  'src/adapters/antigravity/theme-workspace-adapter.js',
  'src/runtime/bootstrap.js',
  'src/runtime/remote-host-runtime.js',
];

const ALL_SOURCE_FILES = [
  ...LIBRARY_SOURCE_FILES,
  'src/runtime/remote-web-entry.js',
  'src/runtime/addon-renderer-entry.js',
];

function sha256(content) {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

function resolveOutDir(argv) {
  const flagIdx = argv.indexOf('--out-dir');
  if (flagIdx !== -1 && typeof argv[flagIdx + 1] === 'string' && argv[flagIdx + 1].trim()) {
    return resolve(ROOT, argv[flagIdx + 1].trim());
  }
  return join(ROOT, 'dist');
}

function buildUserscriptHeader(version) {
  return [
    '// ==UserScript==',
    '// @name         Antigravity Remote Plugin Host',
    '// @namespace    https://github.com/jaeseongs95/antigravity-remote-plugin',
    `// @version      ${version}`,
    '// @description  Cross-device (iOS/Android/Desktop) RemotePlugin.v1 declarative slot host for Antigravity remote web.',
    '// @author       jaeseongs95',
    '// @match        https://antigravity.google.com/*',
    '// @match        https://*.antigravity.google.com/*',
    '// @grant        none',
    '// @run-at       document-idle',
    '// ==/UserScript==',
    '',
  ].join('\n');
}

async function runBuild() {
  const outDir = resolveOutDir(process.argv.slice(2));
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  const pluginManifest = JSON.parse(readFileSync(join(ROOT, 'plugin.json'), 'utf8'));
  const addonManifestRaw = readFileSync(join(ROOT, 'addon-manifest.json'), 'utf8').replace(/\r\n/g, '\n');
  const addonManifest = JSON.parse(addonManifestRaw);

  if (pkg.version !== pluginManifest.version || pkg.version !== addonManifest.version) {
    throw new Error(
      `Version mismatch: package.json (${pkg.version}), plugin.json (${pluginManifest.version}), addon-manifest.json (${addonManifest.version})`,
    );
  }

  const moduleEntries = ALL_SOURCE_FILES.map((relPath) => {
    const absPath = join(ROOT, relPath);
    const content = readFileSync(absPath, 'utf8').replace(/\r\n/g, '\n');
    return {
      path: relPath,
      sha256: sha256(content),
      bytes: Buffer.byteLength(content, 'utf8'),
    };
  });

  // 1) Standalone side-effect-free ESM library bundle (never imports auto-mount browser entries)
  const virtualEntry = [
    `export const BUILD_VERSION = ${JSON.stringify(pkg.version)};`,
    ...LIBRARY_SOURCE_FILES.map((relPath) => `export * from './${relPath}';`),
  ].join('\n');

  const esmResult = await esbuild({
    stdin: {
      contents: virtualEntry,
      resolveDir: ROOT,
      sourcefile: 'virtual-remote-bridge-entry.js',
      loader: 'js',
    },
    bundle: true,
    format: 'esm',
    platform: 'neutral',
    target: 'es2022',
    write: false,
    legalComments: 'none',
    banner: {
      js: [
        `// antigravity-remote-plugin v${pkg.version} — standalone self-contained ESM bundle`,
        `// Built deterministically with esbuild from ${LIBRARY_SOURCE_FILES.length} library modules.`,
      ].join('\n'),
    },
  });

  // 2) Cross-device Userscript (.user.js) IIFE bundle
  const userscriptResult = await esbuild({
    entryPoints: [join(ROOT, 'src/runtime/remote-web-entry.js')],
    bundle: true,
    format: 'iife',
    platform: 'browser',
    target: 'es2022',
    write: false,
    legalComments: 'none',
  });

  // 3) Self-contained minified Bookmarklet (bookmarklet.txt)
  const bookmarkletResult = await esbuild({
    entryPoints: [join(ROOT, 'src/runtime/remote-web-entry.js')],
    bundle: true,
    format: 'iife',
    platform: 'browser',
    target: 'es2022',
    minify: true,
    write: false,
    legalComments: 'none',
  });

  const bookmarkletOut = bookmarkletResult.outputFiles?.[0];
  if (!bookmarkletOut) {
    throw new Error('esbuild failed to emit bookmarklet bundle.');
  }
  const bookmarkletLine = `javascript:${bookmarkletOut.text.replace(/\r\n/g, '\n').trim()}`;

  // 4) Desktop AddonManifest.v1 renderer classic IIFE (consumes host-injected `addonHost`)
  const addonRendererResult = await esbuild({
    entryPoints: [join(ROOT, 'src/runtime/addon-renderer-entry.js')],
    bundle: true,
    format: 'iife',
    platform: 'browser',
    target: 'es2022',
    write: false,
    legalComments: 'none',
    define: {
      __ARP_EMBEDDED_BOOKMARKLET__: JSON.stringify(bookmarkletLine),
    },
    banner: {
      js: `// antigravity-remote-plugin v${pkg.version} — AddonManifest.v1 renderer script (scoped addonHost API only)`,
    },
  });

  const esmOut = esmResult.outputFiles?.[0];
  const userscriptOut = userscriptResult.outputFiles?.[0];
  const addonRendererOut = addonRendererResult.outputFiles?.[0];
  if (!esmOut || !userscriptOut || !addonRendererOut) {
    throw new Error('esbuild failed to emit one or more required bundles.');
  }

  const bundleSource = `${esmOut.text.replace(/\r\n/g, '\n').trimEnd()}\n`;
  const userscriptSource = `${buildUserscriptHeader(pkg.version)}${userscriptOut.text.replace(/\r\n/g, '\n').trimEnd()}\n`;
  const bookmarkletSource = `${bookmarkletLine}\n`;
  const addonRendererSource = `${addonRendererOut.text.replace(/\r\n/g, '\n').trimEnd()}\n`;

  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, 'remote_bridge.js'), bundleSource, 'utf8');
  writeFileSync(join(outDir, 'addon-renderer.js'), addonRendererSource, 'utf8');
  writeFileSync(join(outDir, 'antigravity-remote.user.js'), userscriptSource, 'utf8');
  writeFileSync(join(outDir, 'bookmarklet.txt'), bookmarkletSource, 'utf8');

  const manifest = {
    name: pkg.name,
    version: pkg.version,
    bundler: 'esbuild',
    entry: 'dist/remote_bridge.js',
    entrySha256: sha256(bundleSource),
    addonManifestSha256: sha256(addonManifestRaw),
    artifacts: {
      esm: {
        path: 'dist/remote_bridge.js',
        sha256: sha256(bundleSource),
        bytes: Buffer.byteLength(bundleSource, 'utf8'),
      },
      addonRenderer: {
        path: 'dist/addon-renderer.js',
        sha256: sha256(addonRendererSource),
        bytes: Buffer.byteLength(addonRendererSource, 'utf8'),
      },
      userscript: {
        path: 'dist/antigravity-remote.user.js',
        sha256: sha256(userscriptSource),
        bytes: Buffer.byteLength(userscriptSource, 'utf8'),
      },
      bookmarklet: {
        path: 'dist/bookmarklet.txt',
        sha256: sha256(bookmarkletSource),
        bytes: Buffer.byteLength(bookmarkletSource, 'utf8'),
      },
    },
    moduleCount: moduleEntries.length,
    modules: moduleEntries,
  };

  writeFileSync(join(outDir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');

  console.log(
    `[build] ${pkg.name} v${pkg.version} (esbuild): ${moduleEntries.length} modules -> remote_bridge.js (${manifest.entrySha256.slice(0, 12)}), addon-renderer.js (${manifest.artifacts.addonRenderer.sha256.slice(0, 12)}), antigravity-remote.user.js (${manifest.artifacts.userscript.sha256.slice(0, 12)}), bookmarklet.txt (${manifest.artifacts.bookmarklet.sha256.slice(0, 12)})`,
  );
}

await runBuild();
