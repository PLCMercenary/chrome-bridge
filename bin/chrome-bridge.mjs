#!/usr/bin/env node
// chrome-bridge: MCP (stdio) server and CLI that relay a fixed set of bookmark
// and tab-group commands to the Chrome Bridge extension over an authenticated
// localhost WebSocket.
//
// Lifecycle: the WebSocket port is opened lazily on the first command and
// closed again after IDLE_MS without use, so between agent requests the
// extension finds nothing to connect to and its service worker stays asleep.

import { WebSocketServer } from 'ws';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

const VERSION = '0.1.0';
// Must match PORTS in extension/background.js. Several ports so Claude Code,
// Codex and Cursor can each run their own server at the same time.
const PORTS = [47361, 47362, 47363, 47364, 47365];
const CONF_DIR = path.join(os.homedir(), '.config', 'chrome-bridge');
const SECRET_FILE = path.join(CONF_DIR, 'secret');
const AUDIT_FILE = path.join(CONF_DIR, 'audit.jsonl');
const EXT_DIR = path.resolve(path.dirname(fs.realpathSync(fileURLToPath(import.meta.url))), '..', 'extension');

const IDLE_MS = 5 * 60_000;     // close the port after this long without a command
const WAIT_MS = 45_000;         // extension polls every 30 s, allow for that plus slack
const CALL_MS = 30_000;
const KEEPALIVE_MS = 20_000;    // MV3 service workers sleep after 30 s without WebSocket traffic
const AUTH_MS = 5_000;

const log = (...a) => process.stderr.write('[chrome-bridge] ' + a.join(' ') + '\n'); // stdout is the MCP channel

function readSecret() {
  try {
    const s = fs.readFileSync(SECRET_FILE, 'utf8').trim();
    if (!/^[0-9a-f]{64}$/.test(s)) throw new Error('bad secret format');
    return s;
  } catch {
    throw new Error(`No pairing secret at ${SECRET_FILE}. Run: chrome-bridge pair`);
  }
}

const hmac = (secret, msg) => crypto.createHmac('sha256', Buffer.from(secret, 'hex')).update(msg).digest('hex');
const safeEq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

class Bridge {
  constructor() {
    this.wss = null;
    this.port = null;
    this.conn = null;
    this.pending = new Map();
    this.waiters = [];
    this.seq = 0;
    this.lastUse = 0;
    this.timer = null;
  }

  // Memoized so concurrent tool calls share one listener instead of racing to
  // bind every port in the range.
  ensureListening() {
    this.listening ??= this.listen().catch((e) => { this.listening = null; throw e; });
    return this.listening;
  }

  async listen() {
    this.secret = readSecret();
    for (const port of PORTS) {
      try {
        this.wss = await new Promise((resolve, reject) => {
          const wss = new WebSocketServer({
            host: '127.0.0.1',
            port,
            maxPayload: 8 * 1024 * 1024,
            // Only a browser extension may connect: blocks web pages (Origin
            // http/https) and DNS-rebinding tricks (Host not loopback).
            verifyClient: ({ origin, req }) =>
              typeof origin === 'string' && origin.startsWith('chrome-extension://') &&
              req.headers.host === `127.0.0.1:${port}`,
          });
          wss.once('listening', () => resolve(wss));
          wss.once('error', reject);
        });
        this.port = port;
        break;
      } catch (e) {
        if (e.code !== 'EADDRINUSE') throw e;
      }
    }
    if (!this.wss) throw new Error(`All bridge ports (${PORTS.join(', ')}) are in use`);
    this.wss.on('connection', (ws) => this.onConnection(ws));
    this.timer = setInterval(() => this.tick(), KEEPALIVE_MS);
    this.timer.unref();
    log(`listening on 127.0.0.1:${this.port}`);
  }

  stop(reason) {
    if (!this.wss) return;
    log(`closing port ${this.port}: ${reason}`);
    clearInterval(this.timer);
    for (const ws of this.wss.clients) ws.close(1000, reason);
    this.wss.close();
    this.wss = null;
    this.conn = null;
    this.listening = null;
  }

  tick() {
    if (Date.now() - this.lastUse > IDLE_MS && this.pending.size === 0) return this.stop('idle');
    if (this.conn) this.conn.send('{"type":"ping"}');
  }

  onConnection(ws) {
    const serverNonce = crypto.randomBytes(16).toString('hex');
    let authed = false;
    const authTimer = setTimeout(() => ws.close(4001, 'auth timeout'), AUTH_MS);
    ws.send(JSON.stringify({ type: 'challenge', nonce: serverNonce, v: 1 }));

    ws.on('message', (data) => {
      let m;
      try { m = JSON.parse(data); } catch { return ws.close(4002, 'bad json'); }
      if (!authed) {
        if (m.type !== 'auth' || typeof m.nonce !== 'string' || typeof m.mac !== 'string' || m.nonce.length < 16) {
          return ws.close(4003, 'auth required');
        }
        if (!safeEq(hmac(this.secret, `ext|${serverNonce}|${m.nonce}`), m.mac)) {
          log('rejected a connection with a bad HMAC');
          return ws.close(4003, 'auth failed');
        }
        authed = true;
        clearTimeout(authTimer);
        // Prove we hold the secret too, so a rogue local listener can't feed the extension commands.
        ws.send(JSON.stringify({ type: 'ok', mac: hmac(this.secret, `srv|${m.nonce}|${serverNonce}`) }));
        if (this.conn && this.conn !== ws) this.conn.close(1000, 'superseded');
        this.conn = ws;
        for (const w of this.waiters.splice(0)) w(ws);
        return;
      }
      if (m.type === 'res') {
        const p = this.pending.get(m.id);
        if (!p) return;
        this.pending.delete(m.id);
        clearTimeout(p.timer);
        if (m.ok) p.resolve(m.result); else p.reject(new Error(m.error || 'extension error'));
      }
    });

    ws.on('close', () => {
      clearTimeout(authTimer);
      if (this.conn !== ws) return;
      this.conn = null;
      for (const [id, p] of this.pending) {
        clearTimeout(p.timer);
        p.reject(new Error('extension disconnected'));
        this.pending.delete(id);
      }
    });
    ws.on('error', () => {});
  }

  waitForConnection() {
    if (this.conn) return Promise.resolve(this.conn);
    return new Promise((resolve, reject) => {
      const waiter = (ws) => { clearTimeout(t); resolve(ws); };
      const t = setTimeout(() => {
        this.waiters = this.waiters.filter((w) => w !== waiter);
        reject(new Error(
          `Chrome Bridge extension did not connect within ${WAIT_MS / 1000}s. ` +
          'Check that Chrome is running and the extension is loaded and enabled (toolbar popup).'));
      }, WAIT_MS);
      this.waiters.push(waiter);
    });
  }

  async call(method, params = {}) {
    this.lastUse = Date.now();
    await this.ensureListening();
    const ws = await this.waitForConnection();
    const id = ++this.seq;
    try {
      return await new Promise((resolve, reject) => {
        const timer = setTimeout(() => { this.pending.delete(id); reject(new Error('timed out waiting for the extension')); }, CALL_MS);
        this.pending.set(id, { resolve, reject, timer });
        ws.send(JSON.stringify({ type: 'cmd', id, method, params }));
      });
    } finally {
      this.lastUse = Date.now();
    }
  }
}

// ---------------------------------------------------------------- tools

const parentProps = {
  parentId: { type: 'string', description: 'Parent folder id (from bookmarks_tree).' },
  parentPath: { type: 'string', description: 'Parent folder path, e.g. "Bookmarks bar/ignition/ELN02". Case-insensitive. Synced (account) folders win over local ones.' },
};
const COLORS = ['grey', 'blue', 'red', 'yellow', 'green', 'pink', 'purple', 'cyan', 'orange'];
const urlList = { type: 'array', items: { type: 'string' }, description: 'http/https/file URLs to open as new background tabs.' };
const tabIdList = { type: 'array', items: { type: 'integer' }, description: 'Existing tab ids (from tabs_list).' };

const TOOLS = [
  {
    name: 'bookmarks_tree', method: 'bookmarks.tree',
    description: 'Return the bookmark tree (both synced account and local-only bookmarks). Optionally start at a folder and limit depth.',
    inputSchema: { type: 'object', properties: {
      id: { type: 'string', description: 'Start at this node id.' },
      path: { type: 'string', description: 'Start at this folder path.' },
      depth: { type: 'integer', description: 'Levels of children to include (default unlimited).' },
    } },
  },
  {
    name: 'bookmarks_search', method: 'bookmarks.search',
    description: 'Search bookmarks and folders by title or URL substring. Returns each hit with its folder path.',
    inputSchema: { type: 'object', properties: { query: { type: 'string' } }, required: ['query'] },
  },
  {
    name: 'bookmark_create_folder', method: 'bookmarks.createFolder', mutating: true,
    description: 'Create a bookmark folder. Give parentId or parentPath. With parents=true, missing folders in parentPath are created too.',
    inputSchema: { type: 'object', properties: {
      ...parentProps, title: { type: 'string' }, index: { type: 'integer' },
      parents: { type: 'boolean', description: 'Create missing folders along parentPath.' },
    }, required: ['title'] },
  },
  {
    name: 'bookmark_create', method: 'bookmarks.create', mutating: true,
    description: 'Create a bookmark (http, https or file URL) in a folder.',
    inputSchema: { type: 'object', properties: {
      ...parentProps, title: { type: 'string' }, url: { type: 'string' }, index: { type: 'integer' },
      parents: { type: 'boolean', description: 'Create missing folders along parentPath.' },
    }, required: ['title', 'url'] },
  },
  {
    name: 'bookmark_update', method: 'bookmarks.update', mutating: true,
    description: 'Rename a bookmark or folder, or change a bookmark URL.',
    inputSchema: { type: 'object', properties: {
      id: { type: 'string' }, title: { type: 'string' }, url: { type: 'string' },
    }, required: ['id'] },
  },
  {
    name: 'bookmark_move', method: 'bookmarks.move', mutating: true,
    description: 'Move a bookmark or folder to another folder and/or position.',
    inputSchema: { type: 'object', properties: {
      id: { type: 'string' }, ...parentProps, index: { type: 'integer' },
    }, required: ['id'] },
  },
  {
    name: 'bookmark_remove', method: 'bookmarks.remove', mutating: true,
    description: 'Delete a bookmark or folder. Refuses a non-empty folder unless recursive=true. Deletion syncs to the Google account; the removed subtree is written to the audit log so it can be restored.',
    inputSchema: { type: 'object', properties: {
      id: { type: 'string' }, recursive: { type: 'boolean' },
    }, required: ['id'] },
  },
  {
    name: 'tabs_list', method: 'tabs.list',
    description: 'List open normal windows with their tabs and open tab groups. Saved-but-closed tab groups are not visible to extensions.',
    inputSchema: { type: 'object', properties: { windowId: { type: 'integer' } } },
  },
  {
    name: 'tab_group_create', method: 'groups.create', mutating: true,
    description: 'Create a tab group from new URLs and/or existing tab ids, with a title and color.',
    inputSchema: { type: 'object', properties: {
      title: { type: 'string' }, color: { type: 'string', enum: COLORS },
      urls: urlList, tabIds: tabIdList,
      windowId: { type: 'integer', description: 'Default: last focused window.' },
      collapsed: { type: 'boolean' },
    }, required: ['title'] },
  },
  {
    name: 'tab_group_update', method: 'groups.update', mutating: true,
    description: 'Rename, recolor, collapse or expand an open tab group.',
    inputSchema: { type: 'object', properties: {
      groupId: { type: 'integer' }, title: { type: 'string' }, color: { type: 'string', enum: COLORS }, collapsed: { type: 'boolean' },
    }, required: ['groupId'] },
  },
  {
    name: 'tab_group_add_tabs', method: 'groups.addTabs', mutating: true,
    description: 'Add new URLs and/or existing tabs to an open tab group.',
    inputSchema: { type: 'object', properties: { groupId: { type: 'integer' }, urls: urlList, tabIds: tabIdList }, required: ['groupId'] },
  },
  {
    name: 'tab_group_ungroup', method: 'groups.ungroup', mutating: true,
    description: 'Remove an open tab group but keep its tabs open.',
    inputSchema: { type: 'object', properties: { groupId: { type: 'integer' } }, required: ['groupId'] },
  },
  {
    name: 'tab_group_close', method: 'groups.close', mutating: true,
    description: 'Remove an open tab group by closing all of its tabs. The closed tabs are recorded in the audit log.',
    inputSchema: { type: 'object', properties: { groupId: { type: 'integer' } }, required: ['groupId'] },
  },
];
const TOOL_BY_NAME = new Map(TOOLS.map((t) => [t.name, t]));
const TOOL_BY_METHOD = new Map(TOOLS.map((t) => [t.method, t]));

function audit(entry) {
  try {
    fs.mkdirSync(CONF_DIR, { recursive: true, mode: 0o700 });
    fs.appendFileSync(AUDIT_FILE, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n', { mode: 0o600 });
  } catch (e) {
    log('audit write failed:', e.message);
  }
}

async function runTool(bridge, tool, args) {
  try {
    const result = await bridge.call(tool.method, args);
    if (tool.mutating) audit({ tool: tool.name, args, ok: true, result });
    return result;
  } catch (e) {
    if (tool.mutating) audit({ tool: tool.name, args, ok: false, error: e.message });
    throw e;
  }
}

// ---------------------------------------------------------------- MCP stdio

function serveMcp() {
  const bridge = new Bridge();
  const send = (msg) => process.stdout.write(JSON.stringify(msg) + '\n');
  const rl = readline.createInterface({ input: process.stdin });

  rl.on('line', async (line) => {
    if (!line.trim()) return;
    let msg;
    try { msg = JSON.parse(line); } catch { return send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }); }
    const { id, method, params } = msg;
    if (id === undefined || id === null) return; // notification
    try {
      let result;
      switch (method) {
        case 'initialize':
          result = {
            protocolVersion: params?.protocolVersion || '2025-06-18',
            capabilities: { tools: {} },
            serverInfo: { name: 'chrome-bridge', version: VERSION },
            instructions: 'Manages Chrome bookmarks and tab groups through the Chrome Bridge extension. ' +
              'The first call after an idle period can take up to ~30 s while the extension connects. ' +
              'Deletions sync to the Google account; confirm with the user before removing folders.',
          };
          break;
        case 'ping':
          result = {};
          break;
        case 'tools/list':
          result = { tools: TOOLS.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })) };
          break;
        case 'tools/call': {
          const tool = TOOL_BY_NAME.get(params?.name);
          if (!tool) throw new Error(`unknown tool ${params?.name}`);
          try {
            const out = await runTool(bridge, tool, params.arguments || {});
            result = { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] };
          } catch (e) {
            result = { content: [{ type: 'text', text: `Error: ${e.message}` }], isError: true };
          }
          break;
        }
        default:
          return send({ jsonrpc: '2.0', id, error: { code: -32601, message: `method not found: ${method}` } });
      }
      send({ jsonrpc: '2.0', id, result });
    } catch (e) {
      send({ jsonrpc: '2.0', id, error: { code: -32603, message: e.message } });
    }
  });
  rl.on('close', () => { bridge.stop('stdin closed'); process.exit(0); });
}

// ---------------------------------------------------------------- CLI

function pair() {
  const secret = crypto.randomBytes(32).toString('hex');
  fs.mkdirSync(CONF_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(SECRET_FILE, secret + '\n', { mode: 0o600 });
  fs.chmodSync(SECRET_FILE, 0o600);
  const pairFile = path.join(EXT_DIR, 'pair.json');
  fs.writeFileSync(pairFile, JSON.stringify({ secret }) + '\n', { mode: 0o600 });
  fs.chmodSync(pairFile, 0o600);
  console.log(`New pairing secret written to ${SECRET_FILE} and ${pairFile}.`);
  console.log('Reload the extension in chrome://extensions so it picks up the new secret.');
}

function usage() {
  console.log(`chrome-bridge ${VERSION}
Usage:
  chrome-bridge mcp                     run as an MCP stdio server
  chrome-bridge pair                    generate (or rotate) the shared secret
  chrome-bridge tools                   list tool names and their arguments
  chrome-bridge call <tool> ['<json>']  run one tool, e.g.
      chrome-bridge call bookmarks_tree '{"depth":1}'
      chrome-bridge call tab_group_create '{"title":"ELN2","color":"yellow","urls":["https://example.com"]}'`);
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  switch (cmd) {
    case 'mcp': return serveMcp();
    case 'pair': return pair();
    case 'tools':
      for (const t of TOOLS) console.log(`${t.name}  ${JSON.stringify(Object.keys(t.inputSchema.properties))}${t.mutating ? '  (writes)' : ''}`);
      return;
    case 'call': {
      const tool = TOOL_BY_NAME.get(rest[0]) || TOOL_BY_METHOD.get(rest[0]);
      if (!tool) { console.error(`unknown tool: ${rest[0]}`); process.exit(2); }
      let args = {};
      try { args = rest[1] ? JSON.parse(rest[1]) : {}; } catch { console.error('arguments must be JSON'); process.exit(2); }
      const bridge = new Bridge();
      try {
        console.log(JSON.stringify(await runTool(bridge, tool, args), null, 2));
      } catch (e) {
        console.error(`Error: ${e.message}`);
        process.exitCode = 1;
      } finally {
        bridge.stop('cli done');
      }
      return;
    }
    default:
      usage();
      if (cmd && cmd !== 'help' && cmd !== '-h' && cmd !== '--help') process.exitCode = 2;
  }
}

main();
