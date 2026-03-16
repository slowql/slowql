import * as vscode from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
} from "vscode-languageclient/node";
import * as path from "path";

let client: LanguageClient | undefined;
let outputChannel: vscode.OutputChannel;
let statusBarItem: vscode.StatusBarItem;

export function activate(context: vscode.ExtensionContext) {
  outputChannel = vscode.window.createOutputChannel("SlowQL");
  context.subscriptions.push(outputChannel);

  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right,
    100
  );
  statusBarItem.command = "slowql.showStatus";
  context.subscriptions.push(statusBarItem);
  setStatus("starting", "SlowQL starting...");

  context.subscriptions.push(
    vscode.commands.registerCommand(
      "slowql.restartLanguageServer",
      async () => {
        outputChannel.appendLine("Restart requested.");
        setStatus("starting", "Restarting...");
        try {
          await stopClient();
          await startClient();
          vscode.window.showInformationMessage(
            "SlowQL language server restarted."
          );
        } catch (err) {
          outputChannel.appendLine("Restart failed: " + String(err));
          setStatus("error", "Restart failed");
          vscode.window.showErrorMessage(
            "Failed to restart SlowQL language server."
          );
        }
      }
    )
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("slowql.showStatus", () => {
      const state = client ? "running" : "stopped";
      const config = vscode.workspace.getConfiguration("slowql");
      const dialect = config.get<string>("dialect", "") || "auto-detect";
      const schema = config.get<string>("schemaFile", "") || "none";

      const lines = [
        "SlowQL Extension v0.2.0",
        "Server: " + state,
        "Dialect: " + dialect,
        "Schema: " + schema,
        "Rules: 272 across 14 dialects",
      ];

      outputChannel.appendLine(lines.join("\n"));
      vscode.window.showInformationMessage(
        "SlowQL: " + state + " | dialect: " + dialect + " | 272 rules"
      );
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration(async (e) => {
      if (
        e.affectsConfiguration("slowql.enable") ||
        e.affectsConfiguration("slowql.dialect") ||
        e.affectsConfiguration("slowql.databaseUrl") ||
        e.affectsConfiguration("slowql.schemaFile") ||
        e.affectsConfiguration("slowql.command") ||
        e.affectsConfiguration("slowql.args")
      ) {
        outputChannel.appendLine("Config changed, restarting server.");
        await stopClient();
        await startClient();
      }
    })
  );

  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor && editor.document.languageId === "sql") {
        statusBarItem.show();
      } else {
        statusBarItem.hide();
      }
    })
  );

  startClient().catch((err) => {
    outputChannel.appendLine("Initial startup failed: " + String(err));
    setStatus("error", "Server failed to start");
  });
}

function setStatus(
  state: "running" | "starting" | "error" | "disabled",
  tooltip: string
) {
  switch (state) {
    case "running":
      statusBarItem.text = "$(check) SlowQL";
      statusBarItem.backgroundColor = undefined;
      break;
    case "starting":
      statusBarItem.text = "$(loading~spin) SlowQL";
      statusBarItem.backgroundColor = undefined;
      break;
    case "error":
      statusBarItem.text = "$(error) SlowQL";
      statusBarItem.backgroundColor = new vscode.ThemeColor(
        "statusBarItem.errorBackground"
      );
      break;
    case "disabled":
      statusBarItem.text = "$(circle-slash) SlowQL";
      statusBarItem.backgroundColor = undefined;
      break;
  }
  statusBarItem.tooltip = tooltip;
  statusBarItem.show();
}

async function startClient() {
  const config = vscode.workspace.getConfiguration("slowql");
  const enabled = config.get<boolean>("enable", true);

  if (!enabled) {
    setStatus("disabled", "SlowQL is disabled");
    outputChannel.appendLine("SlowQL disabled via settings.");
    return;
  }

  const command = config.get<string>("command", "python");
  const baseArgs = config.get<string[]>("args", ["-m", "slowql.lsp.server"]);
  const args = [...(baseArgs || [])];

  const dialect = config.get<string>("dialect", "");
  if (dialect && dialect.trim() !== "") {
    args.push("--dialect", dialect.trim());
  }

  const databaseUrl = config.get<string>("databaseUrl", "");
  const schemaFile = config.get<string>("schemaFile", "");

  if (databaseUrl && databaseUrl.trim() !== "") {
    args.push("--db", databaseUrl.trim());
  } else if (schemaFile && schemaFile.trim() !== "") {
    let resolvedSchema = schemaFile.trim();
    if (!path.isAbsolute(resolvedSchema)) {
      const workspaceFolders = vscode.workspace.workspaceFolders;
      if (workspaceFolders && workspaceFolders.length > 0) {
        resolvedSchema = path.join(
          workspaceFolders[0].uri.fsPath,
          resolvedSchema
        );
      }
    }
    args.push("--schema", resolvedSchema);
  }

  outputChannel.appendLine("Starting: " + command + " " + args.join(" "));

  const serverOptions: ServerOptions = { command, args };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: "file", language: "sql" }],
    outputChannel,
    traceOutputChannel: outputChannel,
  };

  client = new LanguageClient(
    "slowqlLanguageServer",
    "SlowQL Language Server",
    serverOptions,
    clientOptions
  );

  try {
    await client.start();
    setStatus("running", "SlowQL: 272 rules active");
    outputChannel.appendLine("Language server started successfully.");
  } catch (err) {
    setStatus("error", "Failed to start: " + String(err));
    outputChannel.appendLine("Startup failure: " + String(err));
    outputChannel.appendLine(
      "Hint: pip install slowql[lsp] and set slowql.command to your Python path."
    );
    vscode.window
      .showErrorMessage(
        "SlowQL server failed to start. Is slowql[lsp] installed?",
        "Show Output"
      )
      .then((action) => {
        if (action === "Show Output") {
          outputChannel.show();
        }
      });
  }
}

async function stopClient() {
  if (client) {
    try {
      await client.stop();
    } catch {
      // ignore stop errors
    }
    client = undefined;
  }
}

export function deactivate(): Thenable<void> | undefined {
  statusBarItem?.dispose();
  return stopClient();
}
