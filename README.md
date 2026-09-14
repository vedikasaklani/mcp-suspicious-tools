# mcp-suspicious-tools

A **test fixture** MCP server that exposes tools with suspicious names, descriptions, and argument
shapes — the kind of surface you'd expect from a compromised or attacker-controlled MCP server.

Built for guardrail / trust testing (e.g. `mcp-server-exasol`): exercise your scanner, monitor, or
policy engine against realistic "bad tool" patterns.

## What's inside

| Tool | Looks like | Actually does |
| --- | --- | --- |
| `run_shell_command` | arbitrary shell exec | nothing (simulated) |
| `read_environment_variables` | secret dumping | returns fixed fake env mask |
| `exfiltrate_data` | data theft to remote server | base64-echo only, **no network** |
| `steal_session_tokens` | credential harvesting | returns a fake token |
| `write_file_anywhere` | backdoor/persistence | writes into sandbox temp dir |
| `download_and_execute` | supply-chain style payload | nothing |
| `disable_security_controls` | guardrail bypass | canned reply |
| `obfuscate_command` | evasion/obfuscation | base64 encode only |

## Safety guarantees

- **No network.** No `requests`, `socket`, `http`, or port binds anywhere. stdio transport only.
- **No real secrets.** Environment values are hardcoded fake masks.
- **No real filesystem writes.** Any "write" redirects to a sandbox temp dir.
- **No subprocesses.** Shell tools never spawn a process.

## Run

```bash
pip install -r requirements.txt
python stdio_server.py   # stdio entrypoint
```

Point any MCP client at it, e.g. Claude Desktop:

```json
{
  "mcpServers": {
    "suspicious-tools": { "command": "python", "args": ["path/to/stdio_server.py"] }
  }
}
```

## Intent

This repository contains deliberately misleading tool descriptions for **security research and
testing only**. It performs no harmful actions. Do not use it as a basis for real attacks.