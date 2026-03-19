# Editor & IDE Setup

Integrating SlowQL directly into your IDE allows vulnerabilities, cost-inefficiencies, and syntax errors to be highlighted under your cursor in real-time as you type, entirely offline via the internal `slowql-lsp` Language Server.

---

## Visual Studio Code (Officially Supported)

The fastest and most stable way to implement real-time analysis is via the official **SlowQL VS Code Extension**.

1. Navigate to the **Extensions Marketplace** within VS Code (or the web portal).
2. Search for **SlowQL**.
3. Click **Install**.
4. *(Optional)* If SlowQL is installed locally inside an active `venv` or globally via `pip`, the extension will automatically detect the binary. Otherwise, it will prompt you to provide the explicit executable path.

### Configuration (`settings.json`)
The extension reads your workspace `slowql.yaml` natively. However, you can manage the extension directly within your `.vscode/settings.json`:

```json
{
    "slowql.executablePath": "/usr/local/bin/slowql",
    "slowql.dialect": "postgresql",
    "slowql.disableCache": false,
    "slowql.lintOnSave": true
}
```

> [!TIP]
> The extension supports **Quick Fixes** natively via the lightbulb `(Ctrl+.)` menu for any rule carrying a `RemediationMode.SAFE_APPLY` resolution.

---

## Neovim (Community / Experimental)

Because SlowQL utilizes the generic `pygls` framework, it exposes standard LSP sockets. You can easily hook the CLI binary into Neovim's native LSP ecosystems, though it is currently considered experimental.

**Example `nvim-lspconfig` Setup (Lua):**
```lua
local lspconfig = require('lspconfig')
local configs = require('lspconfig.configs')

-- Define the custom slowql server
if not configs.slowql then
  configs.slowql = {
    default_config = {
      cmd = { 'slowql', 'lsp' }, -- Requires the slowql binary in $PATH
      filetypes = { 'sql', 'mysql', 'plsql' },
      root_dir = lspconfig.util.root_pattern(".git", "slowql.yaml"),
      settings = {},
    },
  }
end

-- Attach the server
lspconfig.slowql.setup({})
```

---

## JetBrains / IntelliJ

*JetBrains integration via dedicated plugin is currently not tested or officially supported. We recommend executing SlowQL as a File Watcher or External Tool utilizing the CLI `console` output until an official plugin is released.*
