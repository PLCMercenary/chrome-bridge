<p align="center">
  <img src="assets/logo.svg" width="128" height="128" alt="chrome-bridge logo">
</p>

<h1 align="center">chrome-bridge</h1>

<p align="center">
  Let AI coding agents manage your Chrome bookmarks and tab groups,<br>
  through a small MCP server and an extension that only wakes up when asked.
</p>

---

Agent tools like Claude Code, Codex and Cursor can drive web pages, but they
can't touch the browser itself: bookmark folders, tab groups, which tabs are
open. Chrome only exposes those to extensions. `chrome-bridge` is that
extension plus a tiny [MCP](https://modelcontextprotocol.io) server, so you can
say things like:

> Make bookmarks for every server in this list under `Bookmarks bar/Lab`, then
> open them as a tab group called "Lab" in cyan.

and the agent does it.

## How it works

```
 Claude Code / Codex / Cursor / shell
              │  MCP (stdio) or `chrome-bridge call`
              ▼
   bin/chrome-bridge.mjs ── opens 127.0.0.1:4736x only while in use
              ▲
              │  WebSocket, mutual HMAC handshake
              │
   extension/ (MV3 service worker) ── chrome.bookmarks / tabs / tabGroups
```

- The server opens its port **only when a tool is called** and closes it after
  5 minutes idle.
- The extension's service worker wakes every 30 s (the `chrome.alarms`
  minimum), tries the ports, finds nothing, and goes back to sleep. Nothing
  stays resident for the life of the browser.
- The cost of that design: the first call after an idle period waits up to
  ~30 s for the extension to connect. Calls after that are immediate.
- Up to five servers can run at once (ports 47361-47365), so several agent
  clients can each have their own.

## Security

| Concern | Mitigation |
|---|---|
| Remote access | Binds to `127.0.0.1` only. |
| Web pages connecting to localhost | Connections must present a `chrome-extension://` Origin and a loopback Host header (also blocks DNS rebinding). |
| Another local program posing as either side | Mutual HMAC-SHA256 challenge/response over a 256-bit shared secret. The server proves itself to the extension too, so a rogue listener can't feed it commands. |
| Arbitrary code execution | The extension accepts only a fixed command table. No `eval`, no page access, no content scripts. Bookmark and tab URLs are limited to `http`, `https` and `file` (no `javascript:` bookmarklets). |
| Accidental deletes | Removing a non-empty folder requires `recursive: true`. Root folders can't be removed. Every write is appended to `~/.config/chrome-bridge/audit.jsonl`, including the full contents of anything deleted, so it can be rebuilt. |
| Leaving it on | The toolbar badge shows **ON** while an agent is connected, and the popup has a switch that refuses all connections. |

Out of scope: anything already running as your user account can read the
secret file. That's the same trust boundary as your Chrome profile itself.

## Install

Requires Node 20+ and Chrome 120+.

```sh
git clone https://github.com/PLCMercenary/chrome-bridge.git
cd chrome-bridge
npm ci                         # one dependency: ws
./bin/chrome-bridge.mjs pair   # generates the shared secret
```

`pair` writes the secret to `~/.config/chrome-bridge/secret` and
`extension/pair.json` (both mode 0600, and `pair.json` is gitignored). Run it
again any time to rotate the secret.

Then load the extension:

1. Open `chrome://extensions` and turn on **Developer mode**.
2. Click **Load unpacked** and pick the `extension/` folder.
3. After any `pair` rotation or code update, click the reload icon on the
   extension's card.

Optionally put the CLI on your PATH:

```sh
ln -s "$PWD/bin/chrome-bridge.mjs" ~/.local/bin/chrome-bridge
```

## Connect your agent

Use absolute paths. GUI clients often don't inherit your shell's PATH, so
point at the real `node` binary (`command -v node`).

**Claude Code**

```sh
claude mcp add --scope user chrome-bridge -- "$(command -v node)" "$PWD/bin/chrome-bridge.mjs" mcp
```

**Codex**

```sh
codex mcp add chrome-bridge -- "$(command -v node)" "$PWD/bin/chrome-bridge.mjs" mcp
```

**Cursor** (`~/.cursor/mcp.json`), or any client that takes the usual JSON form:

```json
{
  "mcpServers": {
    "chrome-bridge": {
      "command": "/absolute/path/to/node",
      "args": ["/absolute/path/to/chrome-bridge/bin/chrome-bridge.mjs", "mcp"]
    }
  }
}
```

**Anything else** can use the CLI:

```sh
chrome-bridge tools
chrome-bridge call bookmarks_tree '{"depth": 1}'
chrome-bridge call tab_group_create '{"title":"Docs","color":"blue","urls":["https://developer.chrome.com/docs/extensions"]}'
```

## Tools

| Tool | Writes | What it does |
|---|---|---|
| `bookmarks_tree` | | Bookmark tree, optionally from an `id` or `path`, limited by `depth` |
| `bookmarks_search` | | Title or URL substring search; each hit includes its folder path |
| `bookmark_create_folder` | yes | New folder under `parentId` or `parentPath`; `parents: true` creates missing folders along the way |
| `bookmark_create` | yes | New bookmark, same parent options |
| `bookmark_update` | yes | Rename, or change a bookmark's URL |
| `bookmark_move` | yes | Move to another folder and/or position |
| `bookmark_remove` | yes | Delete; `recursive: true` for non-empty folders |
| `tabs_list` | | Open windows, their tabs, and open tab groups |
| `tab_group_create` | yes | Group new `urls` and/or existing `tabIds`, with `title`, `color`, `collapsed` |
| `tab_group_update` | yes | Rename, recolor, collapse or expand |
| `tab_group_add_tabs` | yes | Add URLs or tabs to a group |
| `tab_group_ungroup` | yes | Remove the group, keep the tabs |
| `tab_group_close` | yes | Remove the group by closing its tabs |

Colors: `grey`, `blue`, `red`, `yellow`, `green`, `pink`, `purple`, `cyan`,
`orange`.

### Folder paths

Paths look like `Bookmarks bar/Work/Servers` and match case-insensitively.
Recent Chrome versions keep two copies of each root folder when you're signed
in: a synced account copy and a local-only copy, merged in the UI. The bridge
searches both and prefers the synced one, so new items sync to your account.
If a name is ambiguous, the error lists the candidate ids so you can use
`parentId` instead.

## Known limits

- **Closed saved tab groups are invisible.** Chrome doesn't expose saved groups
  to extensions while they're closed. Click a group's chip to open it and the
  bridge can see and edit it.
- Whether ungrouping or closing an open *saved* group also deletes the saved
  chip hasn't been verified yet.
- Incognito windows are only visible if you allow the extension in incognito.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `extension did not connect within 45s` | Chrome isn't running, the extension is disabled, or the popup switch is off. Open the popup to check. |
| `No pairing secret` | Run `chrome-bridge pair`, then reload the extension. |
| Connects, then drops immediately | The secrets don't match. Re-run `pair` and reload the extension. |
| `All bridge ports ... are in use` | More than five servers are running. Close a client or two. |
| "WebSocket connection failed" in the extension's error log | Expected while no agent is connected: it's the 30 s check finding nothing. |

## Layout

```
bin/chrome-bridge.mjs     MCP server + CLI (Node, ESM)
extension/manifest.json   MV3 manifest: bookmarks, tabs, tabGroups, alarms, storage
extension/background.js   connection, auth, and the command table
extension/popup.*         on/off switch and connection status
assets/logo.svg           project logo
```
