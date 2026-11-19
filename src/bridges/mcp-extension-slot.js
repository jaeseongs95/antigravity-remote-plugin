import { SecurityPolicyError } from '../security/origin-policy.js';
import { redactSecrets } from '../security/redactor.js';

const DEFAULT_PROTECTED_CONFIG_PATTERNS = Object.freeze([
  /(?:^|\/)config\/config\.json$/i,
  /(?:^|\/)plugins\/[^/]+\/mcp_config\.json$/i,
]);

/**
 * Pure, cross-platform lexical path canonicalizer (resolves \, //, ., .., ~/).
 * Used to prevent path-traversal bypasses against protected config patterns.
 */
export function canonicalizeConfigPath(rawPath) {
  if (typeof rawPath !== 'string' || !rawPath.trim()) {
    throw new SecurityPolicyError(
      'INVALID_CONFIG_PATH',
      'A non-empty targetConfigPath is required for MCP configuration mutations.',
    );
  }

  let normalized = rawPath.trim().replace(/\\/g, '/');
  if (normalized === '~' || normalized.startsWith('~/')) {
    normalized = `/__home__${normalized.slice(1)}`;
  }

  const driveMatch = normalized.match(/^([a-zA-Z]:)(\/.*)?$/);
  const prefix = driveMatch ? driveMatch[1].toLowerCase() : normalized.startsWith('/') ? '/' : '';
  const body = driveMatch ? (driveMatch[2] || '') : normalized;

  const segments = body.split('/');
  const resolved = [];
  for (const seg of segments) {
    if (!seg || seg === '.') {
      continue;
    }
    if (seg === '..') {
      if (resolved.length > 0 && resolved[resolved.length - 1] !== '..') {
        resolved.pop();
      } else if (!prefix) {
        resolved.push('..');
      }
      continue;
    }
    resolved.push(seg);
  }

  const joined = resolved.join('/');
  if (driveMatch) {
    return `${prefix}/${joined}`;
  }
  return prefix ? `/${joined}` : joined;
}

export function assertWritableConfigPath(targetPath, extraProtectedPatterns = []) {
  const canonical = canonicalizeConfigPath(targetPath);
  const allPatterns = [...DEFAULT_PROTECTED_CONFIG_PATTERNS, ...extraProtectedPatterns];
  for (const pattern of allPatterns) {
    if (pattern.test(canonical)) {
      throw new SecurityPolicyError(
        'PROTECTED_CONFIG_PATH',
        'Direct modification of protected host or plugin MCP configuration files is forbidden.',
      );
    }
  }
  return canonical;
}

function isStdioMutation({ transport, serverConfig }) {
  const normalizedTransport = typeof transport === 'string' ? transport.trim().toLowerCase() : '';
  if (normalizedTransport === 'stdio') {
    return true;
  }
  // Fail-closed: if transport is omitted or non-HTTP and a local executable command is supplied, treat as stdio.
  if (serverConfig && typeof serverConfig === 'object') {
    if (typeof serverConfig.command === 'string' && serverConfig.command.trim().length > 0) {
      return true;
    }
  }
  return false;
}

export function assertRemoteMcpMutationAllowed({ transport, serverConfig = null, userConfirmed }) {
  if (isStdioMutation({ transport, serverConfig }) && userConfirmed !== true) {
    throw new SecurityPolicyError(
      'UNCONFIRMED_REMOTE_STDIO',
      'Adding or executing a stdio MCP command over a remote channel requires explicit user confirmation.',
    );
  }
}

/**
 * Optional, decoupled extension slot for future remote MCP management.
 * Operates with zero dependency on legacy globals or merged inject files.
 */
export function createMcpExtensionSlot({
  id = 'mcp-extension-slot',
  pluginName,
  sidecarId = null,
  protectedConfigPatterns = [],
  delegate = null,
}) {
  let mounted = false;

  return {
    id,
    pluginName,
    sidecarId,
    requireSidecar: Boolean(sidecarId),

    async mount({ diagnostics }) {
      mounted = true;
      if (diagnostics) {
        diagnostics.emit({
          level: 'info',
          code: 'MCP_SLOT_MOUNTED',
          source: `bridge.${id}`,
          message: 'Optional MCP extension slot mounted in decoupled mode',
          detail: { hasDelegate: Boolean(delegate) },
        });
      }
      return { decoupled: !delegate };
    },

    async requestServerMutation({ targetConfigPath, transport, serverConfig, userConfirmed = false }) {
      if (!mounted) {
        throw new SecurityPolicyError('BRIDGE_NOT_MOUNTED', `Slot "${id}" is not mounted.`);
      }
      const canonicalPath = assertWritableConfigPath(targetConfigPath, protectedConfigPatterns);
      assertRemoteMcpMutationAllowed({ transport, serverConfig, userConfirmed });

      if (!delegate || typeof delegate.applyMutation !== 'function') {
        return {
          applied: false,
          reason: 'NO_DELEGATE_ATTACHED',
          targetConfigPath: canonicalPath,
          sanitizedPreview: redactSecrets(serverConfig),
        };
      }
      return delegate.applyMutation({
        targetConfigPath: canonicalPath,
        transport,
        serverConfig,
        userConfirmed,
      });
    },

    sanitizeServerView(serverConfig) {
      return redactSecrets(serverConfig);
    },

    dispose() {
      mounted = false;
    },
  };
}
