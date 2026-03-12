"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const node_1 = require("vscode-languageclient/node");
let client;
function activate(context) {
    // Launch the SlowQL LSP server as a Python module via stdio.
    const serverOptions = {
        command: "python",
        args: ["-m", "slowql.lsp.server"],
    };
    const clientOptions = {
        documentSelector: [{ scheme: "file", language: "sql" }],
        outputChannelName: "SlowQL Language Server",
    };
    client = new node_1.LanguageClient("slowqlLanguageServer", "SlowQL Language Server", serverOptions, clientOptions);
    client.start();
}
function deactivate() {
    if (!client) {
        return undefined;
    }
    return client.stop();
}
//# sourceMappingURL=extension.js.map