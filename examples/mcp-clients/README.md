# MCP client configs for Praetor

Ready-to-copy configs that register the Praetor MCP server with each host. Praetor's
server is **stdio**, so every host runs the *same* launch command — only the file
format and the wrapping key differ. These examples use the portable, no-clone
command:

```
uvx --from "git+https://github.com/TyrusRC/praetor.git#subdirectory=mcp-server" praetor-mcp
```

## Which file goes where

| File | Copy into | Merge under |
|---|---|---|
| `claude-code.mcp.json` | project `.mcp.json`, or `~/.claude.json` (user scope) | `mcpServers` |
| `claude-desktop.json` | `claude_desktop_config.json` [1] | `mcpServers` |
| `codex-config.toml` | `~/.codex/config.toml` (or project `.codex/config.toml`) | `[mcp_servers.praetor]` |
| `gemini-settings.json` | `~/.gemini/settings.json` (or project `.gemini/settings.json`) | `mcpServers` |
| `antigravity-mcp_config.json` | `~/.gemini/config/mcp_config.json` [2] | `mcpServers` |
| `cursor.mcp.json` | project `.cursor/mcp.json` (or `~/.cursor/mcp.json`) | `mcpServers` |
| `windsurf-mcp_config.json` | `~/.codeium/windsurf/mcp_config.json` | `mcpServers` |
| `vscode.mcp.json` | project `.vscode/mcp.json` | `servers` [3] |

[1] Claude Desktop config path: macOS `~/Library/Application Support/Claude/claude_desktop_config.json`,
    Windows `%APPDATA%\Claude\claude_desktop_config.json`.
[2] Antigravity (IDE + CLI) shares this file with Gemini CLI. Open it from the agent
    panel: `…` → *Manage MCP Servers* → *View raw config*. It uses standard
    `command`/`args`/`env` for a stdio server like Praetor (`serverUrl` is only for
    remote HTTP servers).
[3] VS Code (Copilot agent mode) wraps servers under `servers`, not `mcpServers`, and
    each entry carries `"type": "stdio"`. `code --add-mcp` also works.

If the target file already has a config block, merge the `praetor` entry in rather
than overwriting the whole file.

## Prefer a one-liner?

Hosts with an `mcp add` command:

```sh
claude mcp add praetor -- uvx --from "git+https://github.com/TyrusRC/praetor.git#subdirectory=mcp-server" praetor-mcp
codex  mcp add praetor -- uvx --from "git+https://github.com/TyrusRC/praetor.git#subdirectory=mcp-server" praetor-mcp
```

## Two things that apply to every host

- **The Burp extension JAR must be loaded in Burp separately** — the client only starts
  the Python server; it does not touch Burp. Build it with `./build.sh` and add it via
  Burp → Extensions → Add → Java.
- The `env` block is **optional**. Defaults are `127.0.0.1:8111`; keep it only if Burp
  runs elsewhere (WSL-NAT / remote — set `BURP_API_HOST` to the Windows-host IP). Full
  variable list: see the root README's *Environment Variables*.
