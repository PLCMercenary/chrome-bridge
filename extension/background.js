// Chrome Bridge service worker.
//
// Every 30 s (the chrome.alarms minimum) it tries the bridge ports on
// 127.0.0.1. Nothing listens there unless an agent has just called a tool, so
// normally each attempt fails instantly and the worker goes back to sleep.
// When a server is up, both sides prove they hold the pairing secret
// (pair.json, written by `chrome-bridge pair`) before any command runs, and
// only the fixed commands in HANDLERS are accepted.

const PORTS = [47361, 47362, 47363, 47364, 47365]; // keep in sync with bin/chrome-bridge.mjs
const ALARM = 'chrome-bridge-poll';
const COLORS = new Set(['grey', 'blue', 'red', 'yellow', 'green', 'pink', 'purple', 'cyan', 'orange']);
const URL_SCHEMES = new Set(['http:', 'https:', 'file:']);

const sockets = new Map(); // port -> WebSocket (connecting or open)
const authed = new Set();  // ports with an authenticated session

// ---------------------------------------------------------------- lifecycle

async function ensureAlarm() {
  if (!(await chrome.alarms.get(ALARM))) await chrome.alarms.create(ALARM, { periodInMinutes: 0.5 });
}
chrome.runtime.onInstalled.addListener(() => { ensureAlarm(); poll(); });
chrome.runtime.onStartup.addListener(() => { ensureAlarm(); poll(); });
chrome.alarms.onAlarm.addListener((a) => { if (a.name === ALARM) poll(); });
ensureAlarm();

chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  if (msg?.type === 'status') {
    chrome.storage.local.get('enabled').then(({ enabled = true }) =>
      reply({ enabled, connectedPorts: [...authed] }));
    return true;
  }
  if (msg?.type === 'setEnabled') {
    chrome.storage.local.set({ enabled: !!msg.enabled }).then(() => {
      if (msg.enabled) poll();
      else for (const ws of sockets.values()) ws.close();
      reply({ ok: true });
    });
    return true;
  }
});

function updateBadge() {
  chrome.action.setBadgeText({ text: authed.size ? 'ON' : '' });
  chrome.action.setBadgeBackgroundColor({ color: '#2e7d32' });
}

// ---------------------------------------------------------------- auth + transport

let keyPromise = null;
function getKey() {
  keyPromise ??= (async () => {
    const r = await fetch(chrome.runtime.getURL('pair.json'), { cache: 'no-store' });
    if (!r.ok) throw new Error('pair.json missing: run `chrome-bridge pair`, then reload the extension');
    const { secret } = await r.json();
    if (!/^[0-9a-f]{64}$/.test(secret || '')) throw new Error('pair.json has a malformed secret');
    const bytes = new Uint8Array(secret.match(/../g).map((h) => parseInt(h, 16)));
    return crypto.subtle.importKey('raw', bytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  })();
  keyPromise.catch(() => { keyPromise = null; });
  return keyPromise;
}

const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const mac = async (key, msg) => toHex(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg)));
const randHex = (n) => toHex(crypto.getRandomValues(new Uint8Array(n)));

function constEq(a, b) {
  if (typeof a !== 'string' || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

async function poll() {
  const { enabled = true } = await chrome.storage.local.get('enabled');
  if (!enabled) return;
  let key;
  try { key = await getKey(); } catch (e) { console.warn('[chrome-bridge]', e.message); return; }
  for (const port of PORTS) if (!sockets.has(port)) connect(port, key);
}

function connect(port, key) {
  let ws;
  try { ws = new WebSocket(`ws://127.0.0.1:${port}`); } catch { return; }
  sockets.set(port, ws);
  let serverNonce = null;
  let myNonce = null;
  let ok = false;

  ws.onmessage = async (ev) => {
    let m;
    try { m = JSON.parse(ev.data); } catch { return ws.close(); }
    if (!ok) {
      if (m.type === 'challenge' && !serverNonce && typeof m.nonce === 'string') {
        serverNonce = m.nonce;
        myNonce = randHex(16);
        ws.send(JSON.stringify({ type: 'auth', nonce: myNonce, mac: await mac(key, `ext|${serverNonce}|${myNonce}`) }));
        return;
      }
      if (m.type === 'ok' && myNonce && constEq(m.mac, await mac(key, `srv|${myNonce}|${serverNonce}`))) {
        ok = true;
        authed.add(port);
        updateBadge();
        return;
      }
      return ws.close(); // server failed to prove it holds the secret
    }
    if (m.type === 'ping') return ws.send('{"type":"pong"}');
    if (m.type !== 'cmd') return;
    let out;
    try {
      const handler = Object.hasOwn(HANDLERS, m.method) ? HANDLERS[m.method] : null;
      if (!handler) throw new Error(`unsupported method ${m.method}`);
      out = { type: 'res', id: m.id, ok: true, result: await handler(m.params || {}) };
    } catch (e) {
      out = { type: 'res', id: m.id, ok: false, error: String(e?.message || e) };
    }
    ws.send(JSON.stringify(out));
  };
  ws.onerror = () => {};
  ws.onclose = () => {
    if (sockets.get(port) === ws) sockets.delete(port);
    authed.delete(port);
    updateBadge();
  };
}

// ---------------------------------------------------------------- validation helpers

function checkUrl(u) {
  let parsed;
  try { parsed = new URL(u); } catch { throw new Error(`invalid URL: ${u}`); }
  if (!URL_SCHEMES.has(parsed.protocol)) throw new Error(`URL scheme not allowed (http, https, file only): ${u}`);
  return parsed.href;
}
const checkColor = (c) => {
  if (c !== undefined && !COLORS.has(c)) throw new Error(`color must be one of ${[...COLORS].join(', ')}`);
  return c;
};
const pick = (o, keys) => Object.fromEntries(keys.filter((k) => o[k] !== undefined).map((k) => [k, o[k]]));

// ---------------------------------------------------------------- bookmarks

function ser(n, depth) {
  const o = { id: n.id, title: n.title };
  if (n.url) o.url = n.url;
  else {
    o.folder = true;
    if (n.folderType) o.folderType = n.folderType;
  }
  if (n.syncing !== undefined) o.synced = n.syncing;
  if (n.parentId) o.parentId = n.parentId;
  if (n.children) {
    if (depth === 0) o.childCount = n.children.length;
    else o.children = n.children.map((c) => ser(c, depth - 1));
  }
  return o;
}

async function roots() {
  return (await chrome.bookmarks.getTree())[0].children;
}

// Resolve "Bookmarks bar/ignition/ELN02". The bar and Other bookmarks exist
// twice (synced account copy and local copy), so each segment searches all
// candidate parents and prefers synced nodes when there is a tie.
async function resolvePath(p, { create = false } = {}) {
  const segs = String(p).split('/').map((s) => s.trim()).filter(Boolean);
  if (!segs.length) throw new Error('empty path');
  const eq = (a, b) => a.toLowerCase() === b.toLowerCase();
  const preferSynced = (list) => {
    if (list.length <= 1) return list;
    const synced = list.filter((n) => n.syncing);
    return synced.length ? synced : list;
  };
  let level = (await roots()).filter((r) => eq(r.title, segs[0]));
  if (!level.length) {
    const names = [...new Set((await roots()).map((r) => r.title))];
    throw new Error(`no root folder "${segs[0]}" (roots: ${names.join(', ')})`);
  }
  for (let i = 1; i < segs.length; i++) {
    let next = [];
    for (const parent of level) {
      const kids = await chrome.bookmarks.getChildren(parent.id);
      next.push(...kids.filter((k) => !k.url && eq(k.title, segs[i])));
    }
    next = preferSynced(next);
    if (!next.length) {
      if (!create) throw new Error(`folder "${segs.slice(0, i + 1).join('/')}" not found`);
      next = [await chrome.bookmarks.create({ parentId: preferSynced(level)[0].id, title: segs[i] })];
    }
    level = next;
  }
  const hits = preferSynced(level);
  if (hits.length > 1) throw new Error(`path "${p}" is ambiguous: ids ${hits.map((h) => h.id).join(', ')}`);
  return hits[0];
}

async function parentIdFrom(params) {
  if (params.parentId) return String(params.parentId);
  if (params.parentPath) return (await resolvePath(params.parentPath, { create: !!params.parents })).id;
  throw new Error('parentId or parentPath is required');
}

async function pathOf(id) {
  const parts = [];
  let cur = (await chrome.bookmarks.get(id))[0];
  while (cur?.parentId) {
    cur = (await chrome.bookmarks.get(cur.parentId))[0];
    if (cur?.title) parts.unshift(cur.title);
  }
  return parts.join('/');
}

// ---------------------------------------------------------------- tabs

async function targetWindowId(windowId) {
  if (windowId !== undefined) return windowId;
  return (await chrome.windows.getLastFocused({ windowTypes: ['normal'] })).id;
}

async function openTabs(windowId, urls = []) {
  const ids = [];
  for (const u of urls) ids.push((await chrome.tabs.create({ windowId, url: checkUrl(u), active: false })).id);
  return ids;
}

const serGroup = (g) => pick(g, ['id', 'title', 'color', 'collapsed', 'windowId']);

async function groupTabs(groupId) {
  return chrome.tabs.query({ groupId });
}

// ---------------------------------------------------------------- command table

const HANDLERS = {
  'bookmarks.tree': async ({ id, path, depth }) => {
    const d = Number.isInteger(depth) ? depth : -1;
    if (id || path) {
      const nodeId = id ? String(id) : (await resolvePath(path)).id;
      return ser((await chrome.bookmarks.getSubTree(nodeId))[0], d);
    }
    return (await roots()).map((r) => ser(r, d));
  },

  'bookmarks.search': async ({ query }) => {
    if (!query) throw new Error('query is required');
    const hits = (await chrome.bookmarks.search(String(query))).slice(0, 200);
    return Promise.all(hits.map(async (h) => ({ ...ser(h, 0), path: await pathOf(h.id) })));
  },

  'bookmarks.createFolder': async (p) => {
    if (!p.title) throw new Error('title is required');
    const node = await chrome.bookmarks.create({ parentId: await parentIdFrom(p), title: String(p.title), ...pick(p, ['index']) });
    return ser(node, 0);
  },

  'bookmarks.create': async (p) => {
    if (!p.title || !p.url) throw new Error('title and url are required');
    const node = await chrome.bookmarks.create({
      parentId: await parentIdFrom(p), title: String(p.title), url: checkUrl(p.url), ...pick(p, ['index']),
    });
    return ser(node, 0);
  },

  'bookmarks.update': async ({ id, title, url }) => {
    if (!id) throw new Error('id is required');
    const changes = {};
    if (title !== undefined) changes.title = String(title);
    if (url !== undefined) changes.url = checkUrl(url);
    if (!Object.keys(changes).length) throw new Error('nothing to change: give title and/or url');
    return ser(await chrome.bookmarks.update(String(id), changes), 0);
  },

  'bookmarks.move': async (p) => {
    if (!p.id) throw new Error('id is required');
    const dest = {};
    if (p.parentId || p.parentPath) dest.parentId = await parentIdFrom(p);
    if (p.index !== undefined) dest.index = p.index;
    if (!Object.keys(dest).length) throw new Error('give parentId/parentPath and/or index');
    return ser(await chrome.bookmarks.move(String(p.id), dest), 0);
  },

  'bookmarks.remove': async ({ id, recursive }) => {
    if (!id) throw new Error('id is required');
    const node = (await chrome.bookmarks.getSubTree(String(id)))[0];
    if (!node.parentId || node.parentId === '0') throw new Error('refusing to remove a root folder');
    const snapshot = { ...ser(node, -1), path: await pathOf(node.id) };
    if (!node.url) {
      if (node.children?.length && !recursive) {
        throw new Error(`folder "${node.title}" has ${node.children.length} item(s); pass recursive=true to delete it all`);
      }
      await chrome.bookmarks.removeTree(node.id);
    } else {
      await chrome.bookmarks.remove(node.id);
    }
    return { removed: snapshot };
  },

  'tabs.list': async ({ windowId }) => {
    let wins = await chrome.windows.getAll({ populate: true, windowTypes: ['normal'] });
    if (windowId !== undefined) wins = wins.filter((w) => w.id === windowId);
    const groups = await chrome.tabGroups.query({});
    return wins.map((w) => ({
      id: w.id,
      focused: w.focused,
      groups: groups.filter((g) => g.windowId === w.id).map(serGroup),
      tabs: w.tabs.map((t) => ({
        id: t.id, index: t.index, title: t.title, url: t.url,
        ...(t.groupId >= 0 ? { groupId: t.groupId } : {}),
        ...(t.active ? { active: true } : {}), ...(t.pinned ? { pinned: true } : {}),
      })),
    }));
  },

  'groups.create': async (p) => {
    if (!p.title) throw new Error('title is required');
    checkColor(p.color);
    const windowId = await targetWindowId(p.windowId);
    const tabIds = [...(p.tabIds || []), ...(await openTabs(windowId, p.urls))];
    if (!tabIds.length) throw new Error('give urls and/or tabIds');
    const groupId = await chrome.tabs.group({ tabIds, createProperties: { windowId } });
    const g = await chrome.tabGroups.update(groupId, { title: String(p.title), ...pick(p, ['color', 'collapsed']) });
    return { ...serGroup(g), tabIds };
  },

  'groups.update': async (p) => {
    if (p.groupId === undefined) throw new Error('groupId is required');
    checkColor(p.color);
    const changes = pick(p, ['title', 'color', 'collapsed']);
    if (!Object.keys(changes).length) throw new Error('nothing to change');
    return serGroup(await chrome.tabGroups.update(p.groupId, changes));
  },

  'groups.addTabs': async ({ groupId, urls, tabIds = [] }) => {
    if (groupId === undefined) throw new Error('groupId is required');
    const g = await chrome.tabGroups.get(groupId);
    const ids = [...tabIds, ...(await openTabs(g.windowId, urls))];
    if (!ids.length) throw new Error('give urls and/or tabIds');
    await chrome.tabs.group({ groupId, tabIds: ids });
    return { ...serGroup(g), added: ids };
  },

  'groups.ungroup': async ({ groupId }) => {
    if (groupId === undefined) throw new Error('groupId is required');
    const g = serGroup(await chrome.tabGroups.get(groupId));
    const tabs = await groupTabs(groupId);
    await chrome.tabs.ungroup(tabs.map((t) => t.id));
    return { ungrouped: g, tabIds: tabs.map((t) => t.id) };
  },

  'groups.close': async ({ groupId }) => {
    if (groupId === undefined) throw new Error('groupId is required');
    const g = serGroup(await chrome.tabGroups.get(groupId));
    const tabs = await groupTabs(groupId);
    await chrome.tabs.remove(tabs.map((t) => t.id));
    return { closed: g, tabs: tabs.map((t) => ({ title: t.title, url: t.url })) };
  },
};
