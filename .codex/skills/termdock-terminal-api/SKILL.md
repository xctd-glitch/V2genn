---
name: termdock-terminal-api
description: "Uses the local Termdock Terminal API to control raw terminal sessions or provider-backed agent sessions when direct interactive terminal tools are unavailable."
---

# Termdock Terminal API

## When to Use This Skill

**Use Terminal API when:**
- You need Termdock-local shell control but do not have direct interactive terminal tool access
- You want a raw workspace-bound terminal session
- You want a provider-backed Claude / Codex / Gemini session with attach / status / transcript APIs
- You need polling or SSE supervision from another local agent or skill

**Skip Terminal API when:**
- You already have direct terminal control in the current harness
- You only need filesystem reads or literal searches
- The task is purely code-navigation and AST API already answers it

**Default rule:** Use Terminal API for local terminal orchestration. Use Telegram/Discord only for human remote control.

## Preconditions

1. Termdock must be running locally
2. `Settings -> Remote Control -> Terminal API` must be enabled
3. A Terminal API token must be generated

Base URL:
- Dev: `http://127.0.0.1:3036`
- Prod: `http://127.0.0.1:3037`

Auth:
```bash
Authorization: Bearer $TERMINAL_API_TOKEN
```

## Choose the Right Surface

### Terminal sessions

Use when you want raw shell or TUI control.

Key endpoints:
- `GET /api/terminal/workspaces`
- `POST /api/terminal/sessions`
- `POST /api/terminal/sessions/:id/input`
- `POST /api/terminal/sessions/:id/submit`
- `GET /api/terminal/sessions/:id/output`
- `GET /api/terminal/sessions/:id/status`
- `GET /api/terminal/sessions/:id/log`
- `POST /api/terminal/sessions/:id/keys`
- `GET /api/terminal/layout`
- `POST /api/terminal/layout`
- `POST /api/terminal/layout/panes/:paneId/assign`
- `POST /api/terminal/layout/panes/:paneId/activate`
- `DELETE /api/terminal/sessions/:id`

### Agent sessions

Use when you want Termdock-managed Claude / Codex / Gemini session control.

Key endpoints:
- `POST /api/agent-sessions`
- `GET /api/agent-sessions`
- `POST /api/agent-sessions/resolve`
- `POST /api/agent-sessions/attach`
- `GET /api/agent-sessions/:id`
- `POST /api/agent-sessions/:id/input`
- `POST /api/agent-sessions/:id/restart`
- `DELETE /api/agent-sessions/:id`
- `GET /api/agent-sessions/:id/events`
- `GET /api/agent-sessions/:id/rendered`
- `GET /api/agent-sessions/:id/rendered/stream`

## Quick Start: Terminal Session

### 1. List workspaces
```bash
curl -s -H "Authorization: Bearer $TERMINAL_API_TOKEN" $TERMINAL_API_BASE/api/terminal/workspaces
```

### 2. Create a workspace-bound terminal session
```bash
curl -s -X POST \
  -H "Authorization: Bearer $TERMINAL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"workspaceId":"<wsId>","cols":300}' \
  $TERMINAL_API_BASE/api/terminal/sessions
```

Session creation accepts optional `cols` (80-500, default 80) and `rows` (24-100, default 24). Use `cols:300` when an agent will read long command echoes.

### 3. Send input
```bash
curl -s -X POST \
  -H "Authorization: Bearer $TERMINAL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data":"npm test","appendEnter":true}' \
  $TERMINAL_API_BASE/api/terminal/sessions/<sessionId>/input
```

For long prompts or multilingual multiline input, prefer plain text:
```bash
curl -s -X POST \
  -H "Authorization: Bearer $TERMINAL_API_TOKEN" \
  -H "Content-Type: text/plain" \
  --data-binary $'your long input here' \
  "$TERMINAL_API_BASE/api/terminal/sessions/<sessionId>/input?appendEnter=true"
```

### 4. Optional: submit interactive input
```bash
curl -s -X POST \
  -H "Authorization: Bearer $TERMINAL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data":"continue","settleMs":1500}' \
  $TERMINAL_API_BASE/api/terminal/sessions/<sessionId>/submit
```

Use this only when the terminal is already sitting on an interactive prompt. It is not the default next step after every normal command.

### 5. Read output

Use `mode=screen` for TUI apps. Use `mode=text` when you need `since`-based incremental polling.

```bash
curl -s -H "Authorization: Bearer $TERMINAL_API_TOKEN" \
  "$TERMINAL_API_BASE/api/terminal/sessions/<sessionId>/output?mode=screen&lines=30"
```

```bash
curl -s -H "Authorization: Bearer $TERMINAL_API_TOKEN" \
  "$TERMINAL_API_BASE/api/terminal/sessions/<sessionId>/output?mode=text&lines=80&since=<nextCursor>"
```

### 6. Inspect status
```bash
curl -s -H "Authorization: Bearer $TERMINAL_API_TOKEN" \
  $TERMINAL_API_BASE/api/terminal/sessions/<sessionId>/status
```

### 7. Destroy session
```bash
curl -s -X DELETE -H "Authorization: Bearer $TERMINAL_API_TOKEN" \
  $TERMINAL_API_BASE/api/terminal/sessions/<sessionId>
```

## Terminal Session Operational Guidance

### Output Modes

| Mode | Best for | Description |
|------|----------|-------------|
| `screen` | TUI apps, interactive CLIs | Reads rendered xterm DOM. Returns what the user sees. No `since` support. |
| `text` | Build logs, streaming output | ANSI stripped, blanks preserved. Supports `since` cursor. |
| `content` | Filtered CLI chrome | Best-effort deduplicated output for noisy TUI chrome. |
| `raw` | Debugging terminal rendering | Full terminal stream with ANSI intact. |

Rule of thumb:

- start with `mode=screen` for interactive CLIs
- use `mode=text` when you need incremental polling with `since`
- use `mode=content` only when you specifically want filtered output

### Status Endpoint Notes

Useful fields from `GET /api/terminal/sessions/:id/status`:

- `activity`
- `hasPrompt`
- `waitingForInput`
- `prompt.kind`

`status.activity` alone is not enough for interactive CLI readiness.

### Layout Rule

`mode=screen` only works when the terminal session is visible in a pane. Use layout control endpoints to split and assign sessions before reading.

### Interactive CLI Guidance

Interactive CLIs such as `claude`, Python REPL, `mysql`, `psql`, `npm create`, or `fzf` need extra care.

Do **not** assume this flow is safe:

1. create session
2. send launch command
3. immediately send the next prompt

Use this flow instead:

1. create session
2. send the launch command
3. wait at least 1-2 seconds before the first readiness check
4. poll output and status for several seconds
5. continue only after ready markers appear

### Ready Signals

Prefer output-based readiness, not status-only readiness.

Useful markers include:

- `Claude Code`
- `❯`
- `/effort`
- other stable shell chrome that appears repeatedly across polls

### Recommended Polling Rule

When launching an interactive CLI:

1. send the launch command
2. wait 1-2 seconds
3. poll output/status repeatedly
4. continue only after ready markers appear
5. if output is still suspicious, inspect `raw` or widen the screen/layout

## Quick Start: Agent Session

### 1. Create a new agent session
```bash
curl -s -X POST \
  -H "Authorization: Bearer $TERMINAL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "provider":"claude",
    "cwd":"/path/to/workspace",
    "prompt":"Summarize the current branch and list open risks."
  }' \
  $TERMINAL_API_BASE/api/agent-sessions
```

Required fields:
- `provider`: `claude` | `codex` | `gemini`
- `cwd`
- `prompt`

Optional:
- `env`
- `settingSources`: `project` | `user` | `local`

### 2. Or resolve + attach to an existing session
```bash
curl -s -X POST \
  -H "Authorization: Bearer $TERMINAL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cwd":"/path/to/workspace","shellPid":12345}' \
  $TERMINAL_API_BASE/api/agent-sessions/resolve
```

```bash
curl -s -X POST \
  -H "Authorization: Bearer $TERMINAL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"provider":"claude","sessionId":"sdk-session-1","cwd":"/path/to/workspace"}' \
  $TERMINAL_API_BASE/api/agent-sessions/attach
```

### 3. Inspect status
```bash
curl -s -H "Authorization: Bearer $TERMINAL_API_TOKEN" \
  $TERMINAL_API_BASE/api/agent-sessions/<sessionId>
```

### 4. Send more input
```bash
curl -s -X POST \
  -H "Authorization: Bearer $TERMINAL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"input":"continue with the implementation"}' \
  $TERMINAL_API_BASE/api/agent-sessions/<sessionId>/input
```

### 5. Stream events or rendered transcript
```bash
curl -N -H "Authorization: Bearer $TERMINAL_API_TOKEN" \
  "$TERMINAL_API_BASE/api/agent-sessions/<sessionId>/events?since=0"
```

`/events` is an SSE endpoint. It replays backlog from `since`, then stays open for future events.

```bash
curl -N -H "Authorization: Bearer $TERMINAL_API_TOKEN" \
  $TERMINAL_API_BASE/api/agent-sessions/<sessionId>/rendered/stream
```

### 6. Restart or kill
```bash
curl -s -X POST -H "Authorization: Bearer $TERMINAL_API_TOKEN" \
  $TERMINAL_API_BASE/api/agent-sessions/<sessionId>/restart
```

```bash
curl -s -X DELETE -H "Authorization: Bearer $TERMINAL_API_TOKEN" \
  $TERMINAL_API_BASE/api/agent-sessions/<sessionId>
```

## Key Rules

- Terminal sessions are still mainly polling-oriented.
- Agent sessions add SSE through `/events` and `/rendered/stream`.
- Use terminal sessions when you need raw shell / TUI control.
- Use agent sessions when you want provider-aware state, attach, restart, and transcript supervision.
- `mode=screen` only works when the terminal session is visible in a pane.
- Agent session streaming does **not** depend on terminal pane visibility.
