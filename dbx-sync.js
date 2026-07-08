// ══════════════════════════════════════════════════════════
// Dropbox-backed account + sync layer for LabDaily
//
// Design: "local-first". All existing DB.g()/DB.s() calls stay
// synchronous and keep reading/writing localStorage exactly as
// before — every other function in the app is unaffected. This
// module only:
//   1. Gates the app behind a Dropbox login (OAuth 2.0 + PKCE,
//      no backend server needed).
//   2. Namespaces localStorage keys by the logged-in Dropbox
//      account id, so switching accounts on a shared computer
//      can't leak data between people.
//   3. Mirrors every DB.s() write up to that account's own
//      Dropbox App folder in the background (debounced), and
//      pulls the latest copy down on login.
// ══════════════════════════════════════════════════════════
(function () {
  const DBX_APP_KEY = 'u8g8u5b61hxesft'; // Full Dropbox access — replaces the old Scoped App (App Folder) key
  const DBX_REDIRECT_URI = location.origin + location.pathname;
  const AUTH_KEY = 'dbx_auth'; // {access_token, refresh_token, account_id, expires_at, name, email, appKey}
  const PKCE_KEY = 'dbx_pkce'; // transient: {verifier, state}
  const SYNC_KEYS = ['cfg', 'records', 'projects', 'atts', 'files', 'cmts', 'team'];
  const DEBOUNCE_MS = 1500;
  // Absolute root for all of this app's Dropbox paths. Full Dropbox apps
  // (needed for cross-account folder sharing) can't rely on the implicit
  // App-folder-relative paths a Scoped App gets, so every path is explicit.
  const DBX_ROOT = '/LabDaily';

  // ── PKCE helpers ──
  function b64url(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function randomString(len) {
    const arr = new Uint8Array(len);
    crypto.getRandomValues(arr);
    return b64url(arr);
  }
  async function sha256(str) {
    const data = new TextEncoder().encode(str);
    return await crypto.subtle.digest('SHA-256', data);
  }

  // ── Auth state ──
  // Stamped with the app key that minted it, so a token saved under a
  // previous Dropbox App (e.g. before switching to Full Dropbox access)
  // is treated as logged-out immediately, instead of only discovered
  // after a failed network round-trip.
  function getAuth() {
    try {
      const a = JSON.parse(localStorage.getItem(AUTH_KEY) || 'null');
      if (a && a.appKey && a.appKey !== DBX_APP_KEY) return null;
      return a;
    } catch { return null; }
  }
  function setAuth(a) { localStorage.setItem(AUTH_KEY, JSON.stringify({ ...a, appKey: DBX_APP_KEY })); }
  function clearAuth() { localStorage.removeItem(AUTH_KEY); }

  function isLoggedIn() {
    const a = getAuth();
    return !!(a && a.access_token && a.account_id);
  }
  function currentUid() {
    const a = getAuth();
    return a ? a.account_id : null;
  }

  // ── Namespaced localStorage keys (wraps the app's existing DB) ──
  function nsKey(k) {
    const uid = currentUid();
    return uid ? `ld_${uid}_${k}` : `ld_${k}`;
  }

  // ── Start login: redirect to Dropbox ──
  async function login() {
    const verifier = randomString(64);
    const state = randomString(24);
    sessionStorage.setItem(PKCE_KEY, JSON.stringify({ verifier, state }));
    const challenge = b64url(await sha256(verifier));
    const url = new URL('https://www.dropbox.com/oauth2/authorize');
    url.searchParams.set('client_id', DBX_APP_KEY);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('code_challenge', challenge);
    url.searchParams.set('code_challenge_method', 'S256');
    url.searchParams.set('redirect_uri', DBX_REDIRECT_URI);
    url.searchParams.set('token_access_type', 'offline');
    url.searchParams.set('state', state);
    location.href = url.toString();
  }

  function logout() {
    clearAuth();
    location.reload();
  }

  // ── Complete OAuth callback (?code=...&state=...) ──
  async function handleCallbackIfPresent() {
    const params = new URLSearchParams(location.search);
    const code = params.get('code');
    const state = params.get('state');
    if (!code) return false;

    const saved = JSON.parse(sessionStorage.getItem(PKCE_KEY) || 'null');
    sessionStorage.removeItem(PKCE_KEY);
    if (!saved || saved.state !== state) {
      console.error('Dropbox OAuth state mismatch');
      history.replaceState({}, '', location.pathname);
      return false;
    }

    const body = new URLSearchParams({
      code, grant_type: 'authorization_code', client_id: DBX_APP_KEY,
      code_verifier: saved.verifier, redirect_uri: DBX_REDIRECT_URI
    });
    const res = await fetch('https://api.dropboxapi.com/oauth2/token', { method: 'POST', body });
    const data = await res.json();
    history.replaceState({}, '', location.pathname);
    if (!res.ok) {
      console.error('Dropbox token exchange failed', data);
      alert('Dropbox login failed: ' + (data.error_description || data.error || 'unknown error'));
      return false;
    }

    const acct = await dbxApi('users/get_current_account', null, data.access_token);
    setAuth({
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_at: Date.now() + (data.expires_in * 1000),
      account_id: acct.account_id,
      name: acct.name?.display_name || 'Researcher',
      email: acct.email || ''
    });
    return true;
  }

  // ── Token refresh ──
  // `force` bypasses the expiry check — needed when Dropbox rejects a
  // not-yet-expired token as invalid (e.g. stale token from before a
  // Development-mode user-limit issue was resolved), since the normal
  // expiry-based refresh would never fire for it otherwise.
  async function ensureFreshToken(force) {
    const a = getAuth();
    if (!a) return null;
    if (!force && Date.now() < a.expires_at - 5 * 60 * 1000) return a.access_token;
    const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: a.refresh_token, client_id: DBX_APP_KEY });
    const res = await fetch('https://api.dropboxapi.com/oauth2/token', { method: 'POST', body });
    const data = await res.json();
    if (!res.ok) { console.error('Dropbox refresh failed', data); clearAuth(); location.reload(); return null; }
    a.access_token = data.access_token;
    a.expires_at = Date.now() + (data.expires_in * 1000);
    setAuth(a);
    return a.access_token;
  }

  // ── Low-level Dropbox API call (RPC-style endpoints) ──
  // Every call retries exactly once, forcing a token refresh, if Dropbox
  // reports invalid_access_token — this recovers from a stale saved token
  // without the user having to manually reconnect Dropbox.
  async function dbxApi(endpoint, args, tokenOverride, isRetry) {
    const token = tokenOverride || await ensureFreshToken(isRetry);
    if (!token) throw new Error('Dropbox session expired — please reconnect.');
    const res = await fetch(`https://api.dropboxapi.com/2/${endpoint}`, {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
      body: args ? JSON.stringify(args) : null
    });
    if (!res.ok) {
      const err = await res.text();
      if (!isRetry && !tokenOverride && err.includes('invalid_access_token')) return dbxApi(endpoint, args, null, true);
      throw new Error(`Dropbox API ${endpoint} failed: ${err}`);
    }
    const text = await res.text();
    return text ? JSON.parse(text) : {};
  }

  async function dbxUploadJson(path, obj, isRetry) {
    const token = await ensureFreshToken(isRetry);
    if (!token) throw new Error('Dropbox session expired — please reconnect.');
    const apiArg = { path, mode: 'overwrite', mute: true };
    const res = await fetch('https://content.dropboxapi.com/2/files/upload', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Dropbox-API-Arg': JSON.stringify(apiArg),
        'Content-Type': 'application/octet-stream'
      },
      body: JSON.stringify(obj)
    });
    if (!res.ok) {
      const err = await res.text();
      if (!isRetry && err.includes('invalid_access_token')) return dbxUploadJson(path, obj, true);
      throw new Error('Dropbox upload failed: ' + err);
    }
  }

  async function dbxDownloadJson(path, isRetry) {
    const token = await ensureFreshToken(isRetry);
    if (!token) throw new Error('Dropbox session expired — please reconnect.');
    const res = await fetch('https://content.dropboxapi.com/2/files/download', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + token, 'Dropbox-API-Arg': JSON.stringify({ path }) }
    });
    if (res.status === 409) return undefined; // path not found (first-time user)
    if (!res.ok) {
      const err = await res.text();
      if (!isRetry && err.includes('invalid_access_token')) return dbxDownloadJson(path, true);
      throw new Error('Dropbox download failed: ' + err);
    }
    return res.json();
  }

  // ── Pull all data down from Dropbox into (namespaced) localStorage ──
  async function pullAll() {
    for (const k of SYNC_KEYS) {
      try {
        const val = await dbxDownloadJson(`${DBX_ROOT}/data/${k}.json`);
        if (val !== undefined) localStorage.setItem(nsKey(k), JSON.stringify(val));
      } catch (e) {
        console.error('Dropbox pull failed for', k, e);
      }
    }
  }

  // ── Push a single key up to Dropbox (debounced per key) ──
  const pushTimers = {};
  const pushStatusEl = () => document.getElementById('dbx-sync-status');
  let pendingPushes = 0;
  function schedulePush(k) {
    clearTimeout(pushTimers[k]);
    pushTimers[k] = setTimeout(() => doPush(k), DEBOUNCE_MS);
  }
  async function doPush(k) {
    if (!isLoggedIn()) return;
    pendingPushes++;
    updateSyncBadge();
    try {
      const raw = localStorage.getItem(nsKey(k));
      const val = raw ? JSON.parse(raw) : null;
      await dbxUploadJson(`${DBX_ROOT}/data/${k}.json`, val);
    } catch (e) {
      console.error('Dropbox push failed for', k, e);
    } finally {
      pendingPushes--;
      updateSyncBadge();
    }
  }
  function updateSyncBadge() {
    const el = pushStatusEl();
    if (!el) return;
    el.textContent = pendingPushes > 0 ? '⏳ Syncing…' : '✓ Synced to Dropbox';
  }

  // ── Wrap the page's existing DB.g/DB.s so every read/write is
  //    namespaced by account and every write mirrors to Dropbox ──
  function wrapDB() {
    if (typeof DB === 'undefined') return;
    const origG = DB.g.bind(DB);
    const origS = DB.s.bind(DB);
    DB.g = function (k) {
      try { return JSON.parse(localStorage.getItem(nsKey(k)) || 'null'); } catch { return null; }
    };
    DB.s = function (k, v) {
      localStorage.setItem(nsKey(k), JSON.stringify(v));
      if (SYNC_KEYS.includes(k)) schedulePush(k);
    };
  }

  // ── Force an immediate (non-debounced) push, e.g. before generating a
  //    share link so the file is guaranteed to exist first ──
  async function pushNow(k) {
    clearTimeout(pushTimers[k]);
    await doPush(k);
  }

  // ── Re-push every synced key right now — a manual escape hatch for
  //    right after reconnecting under a new Dropbox App/path scheme,
  //    since the debounced background push only fires on the next edit ──
  async function forceResyncAll() {
    for (const k of SYNC_KEYS) await pushNow(k);
  }

  // ── Make sure the app's root folder exists — sharing/share_folder
  //    needs a real folder, unlike files/upload which auto-creates
  //    parent folders along the way ──
  async function ensureRootFolder() {
    try {
      await dbxApi('files/create_folder_v2', { path: DBX_ROOT, autorename: false });
    } catch (e) {
      if (!String(e.message).includes('path/conflict')) throw e; // already exists — fine
    }
  }

  // ── Get (or create) a shareable link to one of this account's own
  //    synced data files — used to distribute the team roster ──
  async function getShareLinkFor(key) {
    const path = `${DBX_ROOT}/data/${key}.json`;
    try {
      const res = await dbxApi('sharing/create_shared_link_with_settings', { path });
      return res.url;
    } catch (e) {
      // Link already exists — look it up instead of failing
      if (String(e.message).includes('shared_link_already_exists')) {
        const res = await dbxApi('sharing/list_shared_links', { path, direct_only: true });
        if (res.links && res.links[0]) return res.links[0].url;
      }
      throw e;
    }
  }

  // ── Fetch JSON from a public Dropbox shared link (no login needed —
  //    used by team members to pull the roster their PI shared) ──
  async function fetchPublicJson(link) {
    let url = link.trim();
    url = url.includes('dl=0') ? url.replace('dl=0', 'dl=1') : (url.includes('dl=1') ? url : url + (url.includes('?') ? '&dl=1' : '?dl=1'));
    const res = await fetch(url);
    if (!res.ok) throw new Error('Could not load that link (HTTP ' + res.status + ')');
    return res.json();
  }

  // ── Member side: share this account's whole LabDaily folder with the
  //    PI's Dropbox account (native Dropbox folder sharing, viewer-only —
  //    the PI's app never needs write access to a member's own data) ──
  async function shareDataFolder(piEmail) {
    await ensureRootFolder();
    let sharedFolderId;
    try {
      const res = await dbxApi('sharing/share_folder', { path: DBX_ROOT });
      sharedFolderId = res['.tag'] === 'async_job_id'
        ? await pollShareFolderJob(res.async_job_id)
        : res.shared_folder_id;
    } catch (e) {
      // Already a shared folder (e.g. re-sharing with a 2nd PI later) —
      // look up its id instead of failing.
      const existing = await findSharedFolderId(DBX_ROOT);
      if (!existing) throw e;
      sharedFolderId = existing;
    }
    await dbxApi('sharing/add_folder_member', {
      shared_folder_id: sharedFolderId,
      members: [{ member: { '.tag': 'email', email: piEmail }, access_level: { '.tag': 'viewer' } }],
      quiet: false
    });
    return sharedFolderId;
  }

  async function pollShareFolderJob(jobId, attempts, delayMs) {
    attempts = attempts || 12; delayMs = delayMs || 1500;
    for (let i = 0; i < attempts; i++) {
      const st = await dbxApi('sharing/check_share_job_status', { async_job_id: jobId });
      if (st['.tag'] === 'complete') return st.shared_folder_id;
      if (st['.tag'] === 'failed') throw new Error('Dropbox folder-sharing job failed.');
      await new Promise(r => setTimeout(r, delayMs));
    }
    throw new Error('Timed out waiting for Dropbox to finish sharing the folder.');
  }

  async function findSharedFolderId(path) {
    try {
      const res = await dbxApi('sharing/list_folders', { limit: 100 });
      const hit = (res.entries || []).find(f => (f.path_lower || '').toLowerCase() === path.toLowerCase());
      return hit ? hit.shared_folder_id : null;
    } catch { return null; }
  }

  // ── PI side: discover folders team members have shared with this
  //    account, and read a member's synced data out of one ──
  async function listSharedFolders() {
    let res = await dbxApi('sharing/list_folders', { limit: 100 });
    let entries = res.entries || [];
    while (res.cursor) {
      res = await dbxApi('sharing/list_folders/continue', { cursor: res.cursor });
      entries = entries.concat(res.entries || []);
    }
    return entries;
  }

  async function readMemberData(mountPath, key) {
    return dbxDownloadJson(`${mountPath}/data/${key}.json`);
  }

  window.LDDropbox = {
    isLoggedIn, login, logout, currentUid,
    getAuth, pullAll, wrapDB, handleCallbackIfPresent,
    pushNow, forceResyncAll, getShareLinkFor, fetchPublicJson,
    shareDataFolder, listSharedFolders, readMemberData
  };
})();
