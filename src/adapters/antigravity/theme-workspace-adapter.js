/**
 * Antigravity implementation of ThemeWorkspaceSyncPort.
 * Tracks host CSS theme variables and active workspace URIs, notifying sidecar
 * bridges on changes so `theme-change` and `workspace-change` stay synchronized.
 */
export function createAntigravityThemeWorkspaceAdapter({
  initialThemeVariables = {},
  initialWorkspaceUris = [],
} = {}) {
  let themeVariables = { ...(initialThemeVariables || {}) };
  let workspaceUris = Array.isArray(initialWorkspaceUris) ? [...initialWorkspaceUris] : [];
  const listeners = new Set();

  function notify(payload) {
    for (const listener of [...listeners]) {
      listener(payload);
    }
  }

  return {
    getThemeVariables() {
      return { ...themeVariables };
    },

    getWorkspaceUris() {
      return [...workspaceUris];
    },

    subscribe(listener) {
      if (typeof listener !== 'function') {
        throw new TypeError('ThemeWorkspaceSyncPort listener must be a function.');
      }
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },

    updateTheme(nextVariables) {
      themeVariables = { ...(nextVariables || {}) };
      notify({ type: 'theme-change', cssVariables: { ...themeVariables } });
    },

    updateWorkspaces(nextUris) {
      workspaceUris = Array.isArray(nextUris) ? [...nextUris] : [];
      notify({ type: 'workspace-change', workspaceUris: [...workspaceUris] });
    },
  };
}
