import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build as esbuild } from 'esbuild';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');

const SOURCE_FILES = [
  'src/security/redactor.js',
  'src/security/origin-policy.js',
  'src/security/trusted-types.js',
  'src/security/script-guard.js',
  'src/security/dom-guard.js',
  'src/core/diagnostics.js',
  'src/core/lifecycle.js',
  'src/core/ports.js',
  'src/core/orchestrator.js',
  'src/bridges/dom-overlay-bridge.js',
  'src/bridges/sidecar-ui-bridge.js',
  'src/bridges/mcp-extension-slot.js',
  'src/adapters/antigravity/discovery-adapter.js',
  'src/adapters/antigravity/frame-adapter.js',
  'src/adapters/antigravity/sidecar-adapter.js',
  'src/adapters/antigravity/settings-adapter.js',
  'src/adapters/antigravity/theme-workspace-adapter.js',
  'src/runtime/bootstrap.js',
];

function sha256(content) {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

async function runBuild() {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  const pluginManifest = JSON.parse(readFileSync(join(ROOT, 'plugin.json'), 'utf8'));

  if (pkg.version !== pluginManifest.version) {
    throw new Error(
      `Version mismatch: package.json (${pkg.version}) !== plugin.json (${pluginManifest.version})`,
    );
  }

  const moduleEntries = SOURCE_FILES.map((relPath) => {
    const absPath = join(ROOT, relPath);
    const content = readFileSync(absPath, 'utf8').replace(/\r\n/g, '\n');
    return {
      path: relPath,
      sha256: sha256(content),
      bytes: Buffer.byteLength(content, 'utf8'),
    };
  });

  const virtualEntry = [
    `export const BUILD_VERSION = ${JSON.stringify(pkg.version)};`,
    ...SOURCE_FILES.map((relPath) => `export * from './${relPath}';`),
  ].join('\n');

  const result = await esbuild({
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
        `// Built deterministically with esbuild from ${SOURCE_FILES.length} source modules.`,
      ].join('\n'),
    },
  });

  const output = result.outputFiles?.[0];
  if (!output) {
    throw new Error('esbuild produced no output bundle.');
  }

  const bundleSource = `${output.text.replace(/\r\n/g, '\n').trimEnd()}\n`;
  const distDir = join(ROOT, 'dist');
  mkdirSync(distDir, { recursive: true });

  const bundlePath = join(distDir, 'remote_bridge.js');
  writeFileSync(bundlePath, bundleSource, 'utf8');

  const manifest = {
    name: pkg.name,
    version: pkg.version,
    bundler: 'esbuild',
    entry: 'dist/remote_bridge.js',
    entrySha256: sha256(bundleSource),
    moduleCount: moduleEntries.length,
    modules: moduleEntries,
  };

  const manifestPath = join(distDir, 'manifest.json');
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');

  console.log(
    `[build] ${pkg.name} v${pkg.version} (esbuild): ${moduleEntries.length} modules -> dist/remote_bridge.js (${manifest.entrySha256.slice(0, 12)})`,
  );
}

await runBuild();
