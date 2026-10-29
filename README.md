# secret-handoff

Give an AI agent a credential without the secret ever entering the chat transcript, tool logs, or model context.

Anything typed into a chat is already gone — it reaches the model provider, the session transcript, and every log and screenshot of the window. You cannot un-share it; rotating the key is the only cleanup. This tool exists so that never has to happen.

It inverts the usual flow. Instead of the human pasting a key into the conversation, the agent creates a **request**, the human fills it in **on their own machine** behind a masked input, and the agent gets back only a **path** or an **environment variable**.

```
 agent ──ask──────────▶ request (metadata only)
                              │
 human ──gui / fill───────────▶ value ──▶ ~/.local/state/agent-secrets (0600)
                              │
 agent ◀──exec / path─────────┘  never the value itself
```

## Why

Agents routinely ask for an API key and users routinely paste one. That single paste puts the credential in the model context, the stored transcript, the provider's logs, and anything that screenshots the window. From that point the only real remedy is rotation.

Agents don't need to *see* a secret to use it. They need to be able to *pass* it to a command. That's what this does.

## Requirements

- Node.js 18+
- macOS for the native popup (`gui`), which needs the Xcode command line tools for `swiftc`. On Linux or headless machines, use `fill` in a terminal instead.

## Install

Copy the folder into your agent's skill directory — for OpenCode:

```bash
git clone https://github.com/JLDynamics/secret-handoff.git \
  ~/.config/opencode/skills/secret-handoff
```

Then resolve the CLI once and keep it in a variable:

```bash
SECRET="$HOME/.config/opencode/skills/secret-handoff/agent-secret.js"
node "$SECRET" help
```

The popup is compiled on first use and cached in `.build/`.

## The loop

**1. Ask.** Say what the credential is and, more importantly, *why* it's needed and how to create one. A vague request gets the wrong key, or a refusal.

```bash
node "$SECRET" ask \
  --name "Tailscale auth key for test VMs" \
  --for "join 3 ephemeral VMs to the tailnet for PR 26757" \
  --hint "tskey-auth-…, reusable + ephemeral, 1-day expiry" \
  --ttl 24
```

**2. Collect it.** On macOS, pop a native window so the human never leaves the chat:

```bash
node "$SECRET" gui <id>
```

A modal appears with the name, the explanation, a masked field, and a *Save securely* button. It exits `0` on save and `2` on decline. On Linux or headless, the human runs this themselves instead:

```bash
node "$SECRET" fill <id>     # hidden input, nothing echoed
```

**3. Use it without reading it.**

```bash
# Preferred: the value arrives as an env var and is never printed.
node "$SECRET" exec <id> --env TAILSCALE_AUTHKEY -- \
  tailscale up --authkey "$TAILSCALE_AUTHKEY"

# Or hand the CLI a 0600 file path.
KEY=$(node "$SECRET" path <id>)
some-cli --from-file "$KEY"
```

**4. Clean up.**

```bash
node "$SECRET" revoke <id>
```

Values also expire on their own (`--ttl`, default 24h) and are swept on the next command.

## Commands

| Command | Purpose |
|---|---|
| `ask --name … --for … [--hint …] [--ttl h] [--json]` | Create a request; prints an id |
| `gui <id>` | macOS: native masked popup (preferred) |
| `fill <id>` | Human side: hidden terminal input |
| `path <id>` | Print a 0600 file holding the value |
| `exec <id> --env NAME -- cmd…` | Run a command with the value in `$NAME` |
| `list` / `status <id>` | Status and time remaining |
| `revoke <id>` / `purge` | Destroy early / clear finished |
| `get <id>` | Last resort — prints the raw value. Avoid. |

## State

Everything lives in `~/.local/state/agent-secrets/` (override with `AGENT_SECRETS_DIR`):

- `requests/` — metadata only, never contains the value
- `store/` — the values
- `files/` — materialized copies for `path`

Directories are `0700`, files `0600`. Expired entries are removed automatically.

## What this protects against — and what it doesn't

It keeps the value out of **model context, transcripts, logs, and screenshots**. That's the realistic threat: every place a chat message gets copied to.

It does **not** protect against an agent that is already compromised. Any process that can run shell commands can read the store. Treat this as hygiene, not as an airtight vault — and still scope keys narrowly and rotate them.

Nor does it help if the human pastes the value into the chat out of habit. The tool's whole point is refusing that path, even when the user offers because they're being helpful.

## Tests

`scripts/selftest.sh` asserts that no agent-facing output ever contains the value:

```bash
bash scripts/selftest.sh
```

## License

MIT — see [LICENSE](LICENSE).
