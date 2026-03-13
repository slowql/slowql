import * as vscode from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;
let outputChannel: vscode.OutputChannel;

export function activate(context: vscode.ExtensionContext) {
  outputChannel = vscode.window.createOutputChannel("SlowQL");
  context.subscriptions.push(outputChannel);

  outputChannel.appendLine("SlowQL extension activated.");

  const restartCommand = vscode.commands.registerCommand(
    "slowql.restartLanguageServer",
    async () => {
      outputChannel.appendLine("Restarting SlowQL language server...");
      try {
        await stopClient();
        await startClient();
        vscode.window.showInformationMessage("SlowQL language server restarted.");
      } catch (err) {
        outputChannel.appendLine(`Restart failed: ${err}`);
        vscode.window.showErrorMessage("Failed to restart SlowQL language server.");
      }
    }
  );
  context.subscriptions.push(restartCommand);

  // Initial start
  startClient().catch((err) => {
    outputChannel.appendLine(`Initial startup failed: ${err}`);
  });
}

async function startClient() {
  const config = vscode.workspace.getConfiguration("slowql");
  const enabled = config.get<boolean>("enable", true);

  if (!enabled) {
    outputChannel.appendLine("SlowQL is disabled in settings.");
    return;
  }

  const command = config.get<string>("command", "python");
  const args = config.get<string[]>("args", ["-m", "slowql.lsp.server"]);

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

  outputChannel.appendLine(`Starting SlowQL with command: ${command} ${args.join(" ")}`);

  try {
    await client.start();
  } catch (err) {
    vscode.window.showErrorMessage(
      "Failed to start SlowQL language server. Check SlowQL installation and extension settings."
    );
    outputChannel.appendLine(`Startup error: ${err}`);
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


