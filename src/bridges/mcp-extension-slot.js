import { SecurityPolicyError } from '../security/origin-policy.js';
import { redactSecrets } from '../security/redactor.js';

const PROTECTED_CONFIG_PATTERNS = Object.freeze([
  /(?:^|[\\/])config[\\/]config\.json$/i,
  /(?:^|[\\/])plugins[\\/][^\\/]+[\\/]mcp_config\.json$/i,
]);

export function assertWritableConfigPath(targetPath) {
  if (typeof targetPath !== 'string' || !targetPath.trim()) {
    throw new SecurityPolicyError('INVALID_CONFIG_PATH', 'Config path must be a non-empty string.');
  }
  const normalized = targetPath.trim();
  for (const pattern of PROTECTED_CONFIG_PATTERNS) {
    if (pattern.test(normalized)) {
      throw new SecurityPolicyError(
        'PROTECTED_CONFIG_PATH',
        'Direct modification of host config.json or plugin-owned mcp_config.json is forbidden.',
      );
    }
  }
}

export function assertRemoteMcpMutationAllowed({ transport, userConfirmed }) {
  const normalizedTransport = typeof transport === 'string' ? transport.trim().toLowerCase() : '';
  if (normalizedTransport === 'stdio' && userConfirmed !== true) {
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
      if (targetConfigPath) {
        assertWritableConfigPath(targetConfigPath);
      }
      assertRemoteMcpMutationAllowed({ transport, userConfirmed });

      if (!delegate || typeof delegate.applyMutation !== 'function') {
        return {
          applied: false,
          reason: 'NO_DELEGATE_ATTACHED',
          sanitizedPreview: redactSecrets(serverConfig),
        };
      }
      return delegate.applyMutation({
        targetConfigPath,
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
