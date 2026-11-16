// TR Proxy admin UI. One Alpine component; no build step.
//
// The page gets everything from the REST API and keeps the status view live
// over the WebSocket, which also tells it when the config changed.

'use strict';

const REDACTED = '<redacted>';

// --- small helpers ---

function splitList(text) {
  return text.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
}

function splitLines(text) {
  return text.split(/\n/).map((s) => s.trim()).filter(Boolean);
}

function intOrNull(v) {
  const s = String(v ?? '').trim();
  return s === '' ? null : Number(s);
}

function formatBytes(n) {
  if (!n) return '0 B';
  const units = ['B', 'kB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1000 && i < units.length - 1) {
    n /= 1000;
    i++;
  }
  return (i === 0 ? n : n.toFixed(n < 10 ? 2 : 1)) + ' ' + units[i];
}

function formatAge(iso, now) {
  if (!iso) return 'never';
  const s = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (s < 60) return s + ' s ago';
  if (s < 3600) return Math.floor(s / 60) + ' min ago';
  if (s < 86400) return Math.floor(s / 3600) + ' h ' + Math.floor((s % 3600) / 60) + ' min ago';
  return Math.floor(s / 86400) + ' d ago';
}

function formatClock(iso) {
  return new Date(iso).toLocaleTimeString([], { hour12: false });
}

// --- form models: the shape the dialogs edit, and back to config entries ---

const forms = {
  keys: {
    title: 'key',
    blank: () => ({ name: '', secretKey: '', generate: true }),
    // Keys are created and deleted, not edited: a key's name is what
    // connections refer to and its secret is never shown again.
    fromConfig: null,
    toConfig: (f) => ({ name: f.name.trim(), secretKey: f.secretKey.trim() }),
  },

  wireguard: {
    title: 'WireGuard connection',
    blank: () => ({
      name: '', localKey: '', addresses: '', publicKey: '', endpoint: '', presharedKey: '',
      keepalive: '', dns: '', mtu: '',
      probeType: '', probeTarget: '', probeInterval: '', probeTimeout: '', probeFailures: '',
    }),
    fromConfig: (w) => ({
      name: w.name,
      localKey: w.localKey,
      addresses: (w.addresses || []).join(', '),
      publicKey: w.peer.publicKey,
      endpoint: w.peer.endpoint,
      presharedKey: w.peer.presharedKey || '',
      keepalive: w.peer.keepalive ?? '',
      dns: (w.dns || []).join(', '),
      mtu: w.mtu || '',
      probeType: w.probe?.type || '',
      probeTarget: w.probe?.target || '',
      probeInterval: w.probe?.interval || '',
      probeTimeout: w.probe?.timeout || '',
      probeFailures: w.probe?.failures || '',
    }),
    toConfig: (f) => {
      const out = {
        name: f.name.trim(),
        localKey: f.localKey,
        addresses: splitList(f.addresses),
        peer: { publicKey: f.publicKey.trim(), endpoint: f.endpoint.trim() },
      };
      if (f.presharedKey.trim()) out.peer.presharedKey = f.presharedKey.trim();
      if (intOrNull(f.keepalive) !== null) out.peer.keepalive = intOrNull(f.keepalive);
      const dns = splitList(f.dns);
      if (dns.length) out.dns = dns;
      if (intOrNull(f.mtu)) out.mtu = intOrNull(f.mtu);

      const tuned = ['probeTarget', 'probeInterval', 'probeTimeout', 'probeFailures'].some((k) => String(f[k]).trim() !== '');
      if (f.probeType || tuned) {
        // A probe entry needs a type; without a choice it is the default
        // one: dns when there is a DNS server, handshake otherwise.
        out.probe = { type: f.probeType || (dns.length ? 'dns' : 'handshake') };
        if (f.probeTarget.trim()) out.probe.target = f.probeTarget.trim();
        if (intOrNull(f.probeInterval)) out.probe.interval = intOrNull(f.probeInterval);
        if (intOrNull(f.probeTimeout)) out.probe.timeout = intOrNull(f.probeTimeout);
        if (intOrNull(f.probeFailures)) out.probe.failures = intOrNull(f.probeFailures);
      }
      return out;
    },
  },

  upstreams: {
    title: 'upstream proxy',
    blank: () => ({ name: '', type: 'http', url: '', authType: 'none', username: '', password: '', token: '' }),
    fromConfig: (u) => ({
      name: u.name,
      type: u.type,
      url: u.url,
      authType: u.auth?.type || 'none',
      username: u.auth?.username || '',
      password: u.auth?.password || '',
      token: u.auth?.token || '',
    }),
    toConfig: (f) => {
      const out = { name: f.name.trim(), type: f.type, url: f.url.trim() };
      if (f.authType === 'basic') out.auth = { type: 'basic', username: f.username, password: f.password };
      // A token is an HTTP proxy login only.
      if (f.authType === 'bearer' && f.type === 'http') out.auth = { type: 'bearer', token: f.token };
      return out;
    },
  },

  listeners: {
    title: 'listener',
    blank: () => ({ name: '', type: 'socks5', port: '', default: '', users: [], disabled: false }),
    fromConfig: (l) => ({
      name: l.name,
      disabled: !!l.disabled,
      type: l.type,
      port: l.port,
      default: l.default || '',
      users: (l.auth?.users || []).map((u) => ({ username: u.username, password: u.password })),
    }),
    toConfig: (f) => {
      const out = { name: f.name.trim(), type: f.type, port: intOrNull(f.port) ?? 0 };
      if (f.default) out.default = f.default;
      if (f.disabled) out.disabled = true;
      if (f.users.length) out.auth = { users: f.users.map((u) => ({ username: u.username.trim(), password: u.password })) };
      return out;
    },
  },

  rules: {
    title: 'rule',
    blank: () => ({ name: '', match: '', via: '', scope: 'all', listeners: [] }),
    fromConfig: (r) => ({
      name: r.name,
      match: (r.match || []).join('\n'),
      via: [].concat(r.via || []).join(', '),
      scope: r.onlyListeners?.length ? 'only' : r.exceptListeners?.length ? 'except' : 'all',
      listeners: [...(r.onlyListeners || r.exceptListeners || [])],
    }),
    toConfig: (f) => {
      const via = splitList(f.via);
      const out = { name: f.name.trim(), match: splitLines(f.match), via: via.length === 1 ? via[0] : via };
      if (f.scope === 'only' && f.listeners.length) out.onlyListeners = f.listeners;
      if (f.scope === 'except' && f.listeners.length) out.exceptListeners = f.listeners;
      return out;
    },
  },
};

// --- the component ---

function app() {
  return {
    ready: false,
    authed: false,
    totp: false,
    login: { username: '', password: '', totp: '', error: '', busy: false },

    view: 'status',
    views: [
      { id: 'status', label: 'Status' },
      { id: 'tunnels', label: 'Tunnels' },
      { id: 'upstreams', label: 'Upstream proxies' },
      { id: 'listeners', label: 'Listeners' },
      { id: 'rules', label: 'Rules' },
      { id: 'raw', label: 'Config as JSON' },
    ],

    cfg: null,
    status: null,
    events: [],
    live: false,
    now: Date.now(),
    notice: '',

    // The open dialog: { kind, isNew, original, form, error, problems, busy }.
    dialog: null,
    raw: { text: '', error: '', problems: [], dirty: false, busy: false },
    routeTest: { listener: '', host: '', result: null, error: '' },

    REDACTED,
    formatBytes,
    formatClock,

    async init() {
      setInterval(() => { this.now = Date.now(); }, 1000);
      window.addEventListener('hashchange', () => this.readHash());
      this.readHash();
      try {
        const s = await this.api('GET', '/api/session');
        this.totp = s.totp;
        this.authed = s.authenticated;
      } catch (e) {
        this.login.error = 'The server did not answer: ' + e.message;
      }
      this.ready = true;
      if (this.authed) await this.start();
    },

    readHash() {
      const id = location.hash.replace('#', '');
      if (this.views.some((v) => v.id === id)) this.view = id;
    },

    show(id) {
      this.view = id;
      history.replaceState(null, '', '#' + id);
    },

    // --- API ---

    async api(method, path, body) {
      const opts = { method, credentials: 'same-origin' };
      if (body !== undefined) {
        opts.headers = { 'Content-Type': 'application/json' };
        opts.body = JSON.stringify(body);
      }
      const resp = await fetch(path, opts);
      const text = await resp.text();
      let data = null;
      try { data = text ? JSON.parse(text) : null; } catch { /* not JSON */ }
      if (resp.status === 401 && path !== '/api/login') {
        this.signedOut();
      }
      if (!resp.ok) {
        const err = new Error(data?.error || resp.statusText || 'request failed');
        err.problems = data?.problems || [];
        err.status = resp.status;
        throw err;
      }
      return data;
    },

    // --- session ---

    async signIn() {
      this.login.busy = true;
      this.login.error = '';
      try {
        await this.api('POST', '/api/login', {
          username: this.login.username, password: this.login.password, totp: this.login.totp,
        });
        this.login.password = '';
        this.login.totp = '';
        this.authed = true;
        await this.start();
      } catch (e) {
        this.login.error = e.status === 401 ? 'Wrong username, password or code.' : e.message;
      } finally {
        this.login.busy = false;
      }
    },

    async signOut() {
      try { await this.api('POST', '/api/logout'); } catch { /* signed out either way */ }
      this.signedOut();
    },

    signedOut() {
      this.authed = false;
      this.closeDialog();
      if (this.ws) this.ws.close();
    },

    async start() {
      await this.loadConfig();
      this.connect();
    },

    // --- live status ---

    connect() {
      const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
      const ws = new WebSocket(`${scheme}://${location.host}/api/ws`);
      this.ws = ws;
      ws.onopen = () => {
        this.live = true;
        this.events = [];
      };
      ws.onmessage = (msg) => {
        const m = JSON.parse(msg.data);
        if (m.type === 'status') this.status = m.status;
        else if (m.type === 'events') this.events = this.events.concat(m.events).slice(-200);
        else if (m.type === 'config-changed') this.loadConfig();
      };
      ws.onclose = () => {
        this.live = false;
        if (this.ws !== ws || !this.authed) return;
        setTimeout(() => this.reconnect(), 2000);
      };
    },

    async reconnect() {
      if (!this.authed) return;
      try {
        const s = await this.api('GET', '/api/session');
        if (!s.authenticated) return this.signedOut();
        await this.loadConfig();
        this.connect();
      } catch {
        setTimeout(() => this.reconnect(), 2000);
      }
    },

    // --- config ---

    async loadConfig() {
      this.cfg = await this.api('GET', '/api/config');
      if (!this.raw.dirty) this.raw.text = JSON.stringify(this.cfg, null, 2);
      if (!this.routeTest.listener && this.cfg.listeners.length) this.routeTest.listener = this.cfg.listeners[0].name;
    },

    get egresses() {
      if (!this.cfg) return [];
      return ['direct', 'block', ...this.cfg.wireguard.map((w) => w.name), ...this.cfg.upstreams.map((u) => u.name)];
    },

    flash(text) {
      this.notice = text;
      clearTimeout(this.noticeTimer);
      this.noticeTimer = setTimeout(() => { this.notice = ''; }, 4000);
    },

    // --- dialogs ---

    add(kind) {
      const form = forms[kind].blank();
      if (kind === 'wireguard' && this.cfg.keys.length) form.localKey = this.cfg.keys[0].name;
      this.openDialog({ kind, isNew: true, original: '', form, error: '', problems: [], busy: false });
    },

    edit(kind, entry) {
      this.openDialog({ kind, isNew: false, original: entry.name, form: forms[kind].fromConfig(entry), error: '', problems: [], busy: false });
    },

    // The dialog is a native modal: the browser keeps focus inside it,
    // makes the page behind it inert and closes it on Escape.
    openDialog(state) {
      this.dialog = state;
      this.$nextTick(() => {
        const el = this.$refs.dialog;
        if (!el.open) el.showModal();
        el.querySelector('input, select, textarea')?.focus();
      });
    },

    closeDialog() {
      const el = this.$refs.dialog;
      if (el.open) el.close(); // its close event clears this.dialog
      else this.dialog = null;
    },

    get dialogTitle() {
      if (!this.dialog) return '';
      const what = forms[this.dialog.kind].title;
      return this.dialog.isNew ? 'Add ' + what : 'Edit ' + what + ' ' + this.dialog.original;
    },

    async save() {
      const d = this.dialog;
      d.busy = true;
      d.error = '';
      d.problems = [];
      try {
        if (d.kind === 'keys' && d.form.generate) {
          await this.api('POST', '/api/keys/generate', { name: d.form.name.trim() });
        } else {
          const entry = forms[d.kind].toConfig(d.form);
          if (d.isNew) await this.api('POST', `/api/${d.kind}`, entry);
          else await this.api('PUT', `/api/${d.kind}/${encodeURIComponent(d.original)}`, entry);
        }
        await this.loadConfig();
        this.closeDialog();
        this.flash('Saved.');
      } catch (e) {
        d.error = e.problems?.length ? 'Not saved. The config would be invalid:' : 'Not saved: ' + e.message;
        d.problems = e.problems || [];
      } finally {
        d.busy = false;
      }
    },

    async remove(kind, name) {
      if (!confirm(`Delete ${forms[kind].title} ${name}?`)) return;
      try {
        await this.api('DELETE', `/api/${kind}/${encodeURIComponent(name)}`);
        await this.loadConfig();
        this.flash('Deleted ' + name + '.');
      } catch (e) {
        alert(`${name} was not deleted.\n\n${[e.message, ...e.problems].join('\n')}`);
      }
    },

    // --- listeners ---

    async setListenerDisabled(l, disabled) {
      try {
        await this.api('POST', `/api/listeners/${encodeURIComponent(l.name)}/${disabled ? 'disable' : 'enable'}`);
        await this.loadConfig();
        this.flash(disabled ? `Disabled ${l.name}. Open connections stay open.` : `Enabled ${l.name}.`);
      } catch (e) {
        alert([e.message, ...(e.problems || [])].join('\n'));
      }
    },

    listenerState(l) {
      if (l.disabled) return { state: 'starting', text: 'disabled' };
      const st = this.status?.listeners.find((x) => x.name === l.name);
      if (st?.error) return { state: 'down', text: 'not listening' };
      return { state: 'up', text: 'listening' };
    },

    // --- tunnels ---

    tunnelStatus(name) {
      return this.status?.tunnels.find((t) => t.name === name) || null;
    },

    handshakeAge(t) {
      return formatAge(t?.lastHandshake, this.now);
    },

    probeText(t) {
      if (!t) return '';
      const p = t.probe;
      if (!p.checked) return p.type + ': waiting';
      if (p.ok) return p.type + ': ' + (p.latencyMs ? p.latencyMs.toFixed(p.latencyMs < 10 ? 1 : 0) + ' ms' : 'ok');
      return p.type + ': ' + (p.error || 'failed');
    },

    async restart(name) {
      try {
        await this.api('POST', `/api/wireguard/${encodeURIComponent(name)}/restart`);
        this.flash('Restarting ' + name + '.');
      } catch (e) {
        alert(e.message);
      }
    },

    async copy(text) {
      try {
        await navigator.clipboard.writeText(text);
        this.flash('Copied.');
      } catch {
        prompt('Copy the public key:', text);
      }
    },

    // --- rules ---

    viaList(rule) {
      return [].concat(rule.via || []);
    },

    scopeText(rule) {
      if (rule.onlyListeners?.length) return 'only on ' + rule.onlyListeners.join(', ');
      if (rule.exceptListeners?.length) return 'not on ' + rule.exceptListeners.join(', ');
      return 'all listeners';
    },

    async moveRule(index, delta) {
      const names = this.cfg.rules.map((r) => r.name);
      const to = index + delta;
      if (to < 0 || to >= names.length) return;
      [names[index], names[to]] = [names[to], names[index]];
      try {
        await this.api('POST', '/api/rules/order', names);
        await this.loadConfig();
      } catch (e) {
        alert(e.message);
      }
    },

    async setDefault(value) {
      const next = JSON.parse(JSON.stringify(this.cfg));
      next.default = value;
      try {
        await this.api('PUT', '/api/config', next);
        await this.loadConfig();
        this.flash('Default route is now ' + value + '.');
      } catch (e) {
        alert([e.message, ...e.problems].join('\n'));
        await this.loadConfig();
      }
    },

    async testRoute() {
      const t = this.routeTest;
      t.error = '';
      t.result = null;
      try {
        t.result = await this.api('POST', '/api/test-route', { listener: t.listener, host: t.host });
      } catch (e) {
        t.error = e.message;
      }
    },

    // --- raw config ---

    async saveRaw() {
      const r = this.raw;
      r.error = '';
      r.problems = [];
      let parsed;
      try {
        parsed = JSON.parse(r.text);
      } catch (e) {
        r.error = 'This is not valid JSON: ' + e.message;
        return;
      }
      r.busy = true;
      try {
        await this.api('PUT', '/api/config', parsed);
        r.dirty = false;
        await this.loadConfig();
        this.flash('Saved.');
      } catch (e) {
        r.error = e.problems?.length ? 'Not saved. The config would be invalid:' : 'Not saved: ' + e.message;
        r.problems = e.problems || [];
      } finally {
        r.busy = false;
      }
    },

    resetRaw() {
      this.raw = { text: JSON.stringify(this.cfg, null, 2), error: '', problems: [], dirty: false, busy: false };
    },

    // --- status view ---

    get recentEvents() {
      return this.events.slice(-60).reverse();
    },

    connectionAge(c) {
      return formatAge(c.started, this.now).replace(' ago', '');
    },
  };
}

window.app = app;
