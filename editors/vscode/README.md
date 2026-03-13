# SlowQL VS Code Extension (Diagnostics Only)

This extension connects VS Code to the **SlowQL** Language Server to provide
real-time diagnostics for SQL files.

## Features

- Activates on `*.sql` files.
- Starts the SlowQL LSP server (`python -m slowql.lsp.server`) via stdio.
- Shows diagnostics in the **Problems** panel.

## Configuration

This extension provides the following settings under the `slowql` namespace:

- `slowql.enable`: Enable/disable the SlowQL language server (default: `true`).
- `slowql.command`: Command to launch the SlowQL language server (default: `"python"`).
- `slowql.args`: Arguments passed to the SlowQL language server command (default: `["-m", "slowql.lsp.server"]`).

## Development / Local Testing

### 1. Install SlowQL with LSP extras

From the repository root:

```bash
pip install -e ".[lsp]"
```

This installs SlowQL in editable mode together with [pygls](https://github.com/openlawlibrary/pygls)
and [lsprotocol](https://github.com/microsoft/lsprotocol).

### 2. Install VS Code extension dependencies

```bash
cd editors/vscode
npm install
```

### 3. Compile the extension

```bash
npm run compile
```

### 4. Launch the Extension Development Host

1. Open the `editors/vscode` folder in VS Code.
2. Press **F5** (or run **Debug → Start Debugging**).
3. A new VS Code window (Extension Development Host) opens.
4. Open any `.sql` file — diagnostics from SlowQL should appear in the
   **Problems** panel.

### Troubleshooting

- Check the **Output** panel → **SlowQL** channel for server
  logs.
- Make sure `python -m slowql.lsp.server` runs without errors in a terminal
  before launching the extension.

## Notes

- This extension does **not** publish to the VS Code Marketplace yet.
- No Marketplace-specific polish (icon, changelog, etc.) has been added.
