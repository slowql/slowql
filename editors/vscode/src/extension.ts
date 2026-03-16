import * as vscode from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
} from "vscode-languageclient/node";
import * as path from "path";

let client: LanguageClient | undefined;
let outputChannel: vscode.OutputChannel;

export function activate(context: vscode.ExtensionContext) {
  outputChannel = vscode.window.createOutputChannel("SlowQL");
  context.subscriptions.push(outputChannel);

  outputChannel.appendLine("SlowQL extension activated.");
  vscode.window.showInformationMessage("SlowQL extension activated");

  const restartCommand = vscode.commands.registerCommand(
    "slowql.restartLanguageServer",
    async () => {
      outputChannel.appendLine("Restart requested.");
      try {
        await stopClient();
        outputChannel.appendLine("Stop complete.");
        await startClient();
        vscode.window.showInformationMessage("SlowQL language server restarted.");
      } catch (err) {
        outputChannel.appendLine(`Restart failed: ${err}`);
        vscode.window.showErrorMessage("Failed to restart SlowQL language server.");
      }
    }
  );
  context.subscriptions.push(restartCommand);

  const showStatusCommand = vscode.commands.registerCommand(
    "slowql.showStatus",
    () => {
      outputChannel.appendLine("Status report requested.");
      vscode.window.showInformationMessage("SlowQL extension is installed and activated.");
      if (client) {
        outputChannel.appendLine("Language client is initialized.");
      } else {
        outputChannel.appendLine("Language client is not initialized yet.");
      }
    }
  );
  context.subscriptions.push(showStatusCommand);

  const configWatcher = vscode.workspace.onDidChangeConfiguration(async (e) => {
    if (
      e.affectsConfiguration("slowql.databaseUrl") ||
      e.affectsConfiguration("slowql.schemaFile") ||
      e.affectsConfiguration("slowql.command") ||
      e.affectsConfiguration("slowql.args")
    ) {
      outputChannel.appendLine("SlowQL config changed — restarting server.");
      await stopClient();
      await startClient();
    }
  });
  context.subscriptions.push(configWatcher);

  // Initial start
  startClient().catch((err) => {
    outputChannel.appendLine(`Initial startup failed: ${err}`);
  });
}

async function startClient() {
  const config = vscode.workspace.getConfiguration("slowql");
  const enabled = config.get<boolean>("enable", true);

  outputChannel.appendLine(`SlowQL enabled: ${enabled}`);

  if (!enabled) {
    return;
  }

  const command = config.get<string>("command", "python");
  const args = config.get<string[]>("args", ["-m", "slowql.lsp.server"]) || [];

  // Append schema args if configured
  const databaseUrl = config.get<string>("databaseUrl", "");
  const schemaFile = config.get<string>("schemaFile", "");

  if (databaseUrl && databaseUrl.trim() !== "") {
    args.push("--db", databaseUrl.trim());
  } else if (schemaFile && schemaFile.trim() !== "") {
    // Resolve relative paths against workspace root
    let resolvedSchema = schemaFile.trim();
    if (!path.isAbsolute(resolvedSchema)) {
      const workspaceFolders = vscode.workspace.workspaceFolders;
      if (workspaceFolders && workspaceFolders.length > 0) {
        resolvedSchema = path.join(workspaceFolders[0].uri.fsPath, resolvedSchema);
      }
    }
    args.push("--schema", resolvedSchema);
  }

  outputChannel.appendLine(`Command: ${command}`);
  outputChannel.appendLine(`Args: ${args.join(" ")}`);

  const serverOptions: ServerOptions = {
    command,
    args,
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: "file", language: "sql" }],
    outputChannel: outputChannel,
    traceOutputChannel: outputChannel,
  };

  client = new LanguageClient(
    "slowqlLanguageServer",
    "SlowQL Language Server",
    serverOptions,
    clientOptions
  );

  outputChannel.appendLine("Startup attempt...");

  try {
    await client.start();
  } catch (err) {
    vscode.window.showErrorMessage(
      "Failed to start SlowQL language server. Check SlowQL installation and extension settings."
    );
    outputChannel.appendLine(`Startup failure: ${err}`);
    outputChannel.appendLine(`Command: ${command}`);
    outputChannel.appendLine(`Args: ${args.join(" ")}`);
    outputChannel.appendLine(
      "Hint: Try setting slowql.command to the full path of your Python interpreter."
    );
  }
}

async function stopClient() {
  if (client) {
    await client.stop();
    client = undefined;
  }
}

export function deactivate(): Thenable<void> | undefined {
  return stopClient();
}


