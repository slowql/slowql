import * as vscode from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
} from "vscode-languageclient/node";

let client: LanguageClient;

export function activate(context: vscode.ExtensionContext) {
  // Launch the SlowQL LSP server as a Python module via stdio.
  const serverOptions: ServerOptions = {
    command: "python",
    args: ["-m", "slowql.lsp.server"],
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: "file", language: "sql" }],
    outputChannelName: "SlowQL Language Server",
  };

  client = new LanguageClient(
    "slowqlLanguageServer",
    "SlowQL Language Server",
    serverOptions,
    clientOptions
  );

  client.start();
}

export function deactivate(): Thenable<void> | undefined {
  if (!client) {
    return undefined;
  }
  return client.stop();
}
