import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');

// Ordered in strict topological dependency order for standalone ESM bundling.
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

function stripRelativeImports(source) {
  return source.replace(
    /^import\s+[\s\S]*?from\s+['"]\.\.?\/[^'"]+['"];\s*$/gm,
    '',
  ).trim();
}

function build() {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  const pluginManifest = JSON.parse(readFileSync(join(ROOT, 'plugin.json'), 'utf8'));

  if (pkg.version !== pluginManifest.version) {
    throw new Error(
      `Version mismatch: package.json (${pkg.version}) !== plugin.json (${pluginManifest.version})`,
    );
  }

  const moduleEntries = [];
  const bundledChunks = [
    `// antigravity-remote-plugin v${pkg.version} — standalone self-contained ESM bundle`,
    `// Generated deterministically from ${SOURCE_FILES.length} source modules.`,
    `export const BUILD_VERSION = ${JSON.stringify(pkg.version)};`,
    '',
  ];

  for (const relPath of SOURCE_FILES) {
    const absPath = join(ROOT, relPath);
    const content = readFileSync(absPath, 'utf8').replace(/\r\n/g, '\n');
    moduleEntries.push({
      path: relPath,
      sha256: sha256(content),
      bytes: Buffer.byteLength(content, 'utf8'),
    });
    bundledChunks.push(`// --- module: ${relPath} ---`);
    bundledChunks.push(stripRelativeImports(content));
    bundledChunks.push('');
  }

  const distDir = join(ROOT, 'dist');
  mkdirSync(distDir, { recursive: true });

  const bundleSource = `${bundledChunks.join('\n').trimEnd()}\n`;
  const bundlePath = join(distDir, 'remote_bridge.js');
  writeFileSync(bundlePath, bundleSource, 'utf8');

  const manifest = {
    name: pkg.name,
    version: pkg.version,
    entry: 'dist/remote_bridge.js',
    entrySha256: sha256(bundleSource),
    moduleCount: moduleEntries.length,
    modules: moduleEntries,
  };

  const manifestPath = join(distDir, 'manifest.json');
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');

  console.log(
    `[build] ${pkg.name} v${pkg.version}: ${moduleEntries.length} modules -> dist/remote_bridge.js (${manifest.entrySha256.slice(0, 12)})`,
  );
}

build();
