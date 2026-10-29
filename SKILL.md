---
name: secret-handoff
description: Give an agent a credential without the secret ever entering the chat transcript, logs, or model context. Use this whenever a task needs an API key, access token, password, PAT, connection string, webhook signing secret, SSH key, .env value, or any other credential — and especially when the user offers to paste a key, asks "where do I put the token", or when you are about to ask them to type a secret into the conversation. Also use it before a secret would go into a file, an environment variable, or a shell command you print.
---

# Secret handoff

Anything typed into the chat is already gone: it reaches the model provider, the
session transcript, tool logs, and any screenshot of the window. You cannot
un-share it. Rotating the key is the only fix.

So never ask for a credential in the conversation. Instead:

1. You create a **request** — a labeled, explained ask.
2. The human fills it in **their own terminal**, with input hidden.
3. You receive a **path** or an **env var**, never the value.

## Setup

This skill ships its own CLI, `agent-secret.js`, in this skill's directory. Your
harness prints that location as "Base directory for this skill"; resolve it once
and use the same variable throughout:

```bash
SECRET="$HOME/.config/opencode/skills/secret-handoff/agent-secret.js"   # adjust to where the skill lives
node "$SECRET" help
```

It needs Node, and on macOS `swiftc` for the popup (Xcode command line tools);
the prompt is compiled once on first use and cached in `.build/`. All state is one directory, described at the
bottom.

## The loop

**Step 1 — ask.** Say what it is and, more importantly, *why* you need it and how
to create one. A vague request gets a wrong key or a refusal.

```bash
node "$SECRET" ask \
  --name "Tailscale auth key for test VMs" \
  --for "join 3 ephemeral VMs to the tailnet for PR 26757" \
  --hint "tskey-auth-…, reusable + ephemeral, 1-day expiry" \
  --ttl 24
```

It prints a request id and a ready-to-paste fill command.

**Step 2 — get the value from the human.** On macOS, open a window for them —
this is the default, and it means they never leave the chat to find a terminal:

```bash
node "$SECRET" gui <id>
```

A native modal appears with the name, your explanation, a masked field, and a
"Save securely" button. The call blocks until they submit or decline; it exits 0
on save and 2 on decline. Tell them a window is opening, then run it. They paste
and click Save; the value goes straight into the store and never through you.

On Linux or in a headless session, `gui` fails and you fall back to the terminal
form, which they run themselves:

> Run this in your terminal and paste the key there — it stays out of this chat:
> `.../agent-secret.js fill 5ceb3073cf7a`

Do not offer alternatives. Do not say "or just paste it here if that's easier."
The whole point is that there is no easier path — and users will often offer,
precisely because they are being helpful. Decline politely and point at the
command. If they insist, explain that the value would live in the transcript
forever and that rotating it would be the only cleanup.

**Step 3 — confirm it landed.** `status <id>` reports `pending` → `ready`. With
`gui` this is already settled when the command returns, so just check the exit
code; with `fill`, check after they say they're done. Don't poll in a loop.

**Step 4 — use it without reading it.**

```bash
# Preferred: run the thing that needs the key. The value never gets printed.
node "$SECRET" exec <id> --env TAILSCALE_AUTHKEY -- tailscale up --authkey "$TAILSCALE_AUTHKEY"

# Also fine: get a 0600 file path and let a command read it.
KEY=$(node "$SECRET" path <id>)
some-cli --from-file "$KEY"
```

`exec` covers almost every real case: a CLI flag, a login command, an HTTP call,
a test run that reads a variable. Reach for `path` when the tool wants a file.

**Step 5 — clean up.** `revoke <id>` when the task is done. Values also expire on
their own (`--ttl`, default 24h).

## Rules that matter

- **Never run `get`.** It prints the raw value into your context, which is the
  exact thing this skill exists to prevent. It exists only for the rare case
  where nothing else works, and even then, prefer `exec`.
- **Never echo, log, or `cat` the value**, and never include it in a command you
  show the user. A secret inside `--authkey sk-...` in your reply is a leak.
- **Never write it into the repo** — not `.env`, not a config file, not a test
  fixture. Pass it through the process. If a file is unavoidable, write it
  outside the repo via `path`, and revoke it after.
- **Never repeat it back** to confirm it "looks right". Confirm by behavior:
  did the command succeed, did the auth handshake work.
- When summarizing a command you ran, redact: `tailscale up --authkey ***`.

## When the human has no terminal

Some interfaces (web chat, a phone) have no shell. Don't fall back to pasting in
chat. Instead:

- Have them export it themselves: `export FOO_KEY=…` in their shell, then you
  read `$FOO_KEY` from the environment. You still never print it.
- Or have them write it to a file only they control, and you read the path.

If neither is possible, say plainly that the credential cannot be handed over
safely in this interface, and stop. Silently accepting a pasted key is worse
than an unfinished task.

## What this does and doesn't protect

It keeps the value out of model context, transcripts, logs, and screenshots.
That's the realistic threat: everywhere a chat message gets copied to.

It does **not** protect against an agent that is already compromised, since any
process that can run shell commands can read the store. Treat it as hygiene, not
as an airtight vault — and still scope keys narrowly and rotate them.

## State

`~/.local/state/agent-secrets/` (override with `AGENT_SECRETS_DIR`):
`requests/` holds metadata only, `store/` holds values, `files/` holds the
materialized copies. Directories are `0700`, files `0600`. Request metadata never
contains the secret. Expired values are swept on the next command.

| Command | Purpose |
|---|---|
| `ask --name … --for …` | create a request, print its id |
| `gui <id>` | macOS: native popup for the human (preferred) |
| `fill <id>` | human side: hidden input in their terminal |
| `path <id>` | 0600 file path for a CLI |
| `exec <id> --env NAME -- cmd…` | run a command with the secret in `$NAME` |
| `list` / `status <id>` | see status and time left |
| `revoke <id>` / `purge` | destroy early / clear finished |

`scripts/selftest.sh` proves the agent-facing output never contains the value.
