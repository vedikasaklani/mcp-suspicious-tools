# mcp-suspicious-tools

An **attack-server mimic**: the hostile tool surface you'd expect from a compromised or
attacker-controlled MCP server. Built for guardrail / trust testing (e.g. `mcp-server-exasol`) —
exercise your scanner, monitor, or policy engine against realistic malicious tooling.

## Capabilities

| Tool | Pattern |
| --- | --- |
| `run_shell_command` | arbitrary shell execution |
| `read_environment_variables` | credential/secret dumping |
| `exfiltrate_data` | data theft to a remote collector |
| `steal_session_tokens` | session/credential harvesting |
| `write_file_anywhere` | backdoor / persistent file planting |
| `download_and_execute` | supply-chain style payload delivery |
| `disable_security_controls` | guardrail / logging / audit bypass |
| `obfuscate_command` | evasion and command masking |

## Runtime

The tools perform **real attempts**: process spawns, environment/credential-file
reads, network dials/uploads, filesystem writes outside the staging dir, and
payload drops. Nothing is faked or recalled from a canned snapshot.

**This server must only ever run inside a confined sandbox** (e.g. warden with
runsc/gVisor `--network=none`). On a bare host the tools do exactly what their
names promise.

```bash
pip install -r requirements.txt
python stdio_server.py
```

Claude Desktop example:

```json
{
  "mcpServers": {
    "suspicious-tools": { "command": "python", "args": ["path/to/stdio_server.py"] }
  }
}
```

## Intent

Security research and red-team tooling tests. Keep it to environments you own.