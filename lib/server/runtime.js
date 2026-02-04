import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { google } from 'googleapis';
import { z } from 'zod';
import { createClient } from '@supabase/supabase-js';

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const LOG_LEVELS = { info: 0, warn: 1, error: 2 };
const CURRENT_LOG_LEVEL = LOG_LEVELS[process.env.LOG_LEVEL] ?? LOG_LEVELS.info;

function log(level, message, meta = {}) {
  if (LOG_LEVELS[level] >= CURRENT_LOG_LEVEL) {
    console.log(
      JSON.stringify({ level, message, ...meta, timestamp: new Date().toISOString() })
    );
  }
}

// ========== ENV VALIDATION ==========
const envSchema = z.object({
  GOOGLE_CLIENT_ID: z.string().min(1),
  GOOGLE_CLIENT_SECRET: z.string().min(1),
  GOOGLE_REDIRECT_URI: z.string().min(1),
  ADMIN_API_KEY: z.string().min(1),
  ALLOWED_ORIGINS: z.string().optional(),
  MAX_MESSAGES: z.string().optional(),
  TOKEN_ENCRYPTION_KEY: z.string().optional(),
  TOKEN_PATH: z.string().optional(),
  DATA_DIR: z.string().optional(),
  SUPABASE_URL: z.string().optional(),
  SUPABASE_SERVICE_ROLE_KEY: z.string().optional(),
  SUPABASE_KV_TABLE: z.string().optional()
});

function loadEnv() {
  const parsed = envSchema.safeParse(process.env);
  if (!parsed.success) {
    throw new Error(
      `Missing required environment variables: ${parsed.error.issues
        .map((i) => i.path.join('.'))
        .join(', ')}`
    );
  }
  return parsed.data;
}

const env = loadEnv();
const ROOT_DIR = process.cwd();
const fsPromises = fs.promises;

const DEFAULT_DATA_DIR = path.join(ROOT_DIR, 'data');
const LEGACY_DATA_DIR = path.join(ROOT_DIR, 'gmail-backend', 'data');
const DATA_DIR = env.DATA_DIR || (fs.existsSync(DEFAULT_DATA_DIR) ? DEFAULT_DATA_DIR : LEGACY_DATA_DIR);

const DEFAULT_TOKEN_PATH = path.join(ROOT_DIR, 'token.json');
const LEGACY_TOKEN_PATH = path.join(ROOT_DIR, 'gmail-backend', 'token.json');
// Prefer new location, fallback to legacy hanya jika ada dan default belum ada
const TOKEN_PATH = env.TOKEN_PATH || DEFAULT_TOKEN_PATH;
const ALIASES_PATH = path.join(DATA_DIR, 'aliases.json');
const DOMAINS_PATH = path.join(DATA_DIR, 'domains.json');
const LOGS_PATH = path.join(DATA_DIR, 'logs.json');
const AUDIT_PATH = path.join(DATA_DIR, 'audit.json');

const ALLOWED_ORIGINS = (env.ALLOWED_ORIGINS || 'http://localhost:3000').split(',')
  .map((v) => v.trim())
  .filter(Boolean);
const MAX_MESSAGES = Math.min(parseInt(env.MAX_MESSAGES || '20', 10) || 20, 50);
const TOKEN_ENCRYPTION_KEY = env.TOKEN_ENCRYPTION_KEY || null;

const SUPABASE_URL = env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY;
const SUPABASE_KV_TABLE = env.SUPABASE_KV_TABLE || 'app_kv';
const USE_SUPABASE_STORAGE = Boolean(SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY);

if (!USE_SUPABASE_STORAGE) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

let supabaseAdmin = null;
function getSupabaseAdmin() {
  if (!USE_SUPABASE_STORAGE) return null;
  if (supabaseAdmin) return supabaseAdmin;
  supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false }
  });
  return supabaseAdmin;
}

const STORAGE_KEYS = {
  [TOKEN_PATH]: 'token',
  [ALIASES_PATH]: 'aliases',
  [DOMAINS_PATH]: 'domains',
  [LOGS_PATH]: 'logs',
  [AUDIT_PATH]: 'audit'
};

function getStorageKey(file) {
  return STORAGE_KEYS[file] || path.basename(file);
}

async function supabaseGet(key) {
  const client = getSupabaseAdmin();
  if (!client) return null;
  const { data, error } = await client
    .from(SUPABASE_KV_TABLE)
    .select('value')
    .eq('key', key)
    .maybeSingle();
  if (error) {
    log('error', 'Supabase get failed', { key, error: error.message });
    return null;
  }
  return data?.value ?? null;
}

async function supabaseSet(key, value) {
  const client = getSupabaseAdmin();
  if (!client) return;
  const { error } = await client
    .from(SUPABASE_KV_TABLE)
    .upsert({ key, value, updated_at: new Date().toISOString() }, { onConflict: 'key' });
  if (error) {
    log('error', 'Supabase set failed', { key, error: error.message });
  }
}

async function fileExists(file) {
  try {
    await fsPromises.access(file);
    return true;
  } catch {
    return false;
  }
}

// ========== FILE HELPERS ==========
function encryptToken(text) {
  if (!TOKEN_ENCRYPTION_KEY) return text;
  const key = Buffer.from(TOKEN_ENCRYPTION_KEY, 'hex');
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return `${iv.toString('hex')}:${encrypted}`;
}

function decryptToken(text) {
  if (!TOKEN_ENCRYPTION_KEY) return text;
  const parts = text.split(':');
  if (parts.length !== 2) throw new Error('Invalid encrypted token format');
  const key = Buffer.from(TOKEN_ENCRYPTION_KEY, 'hex');
  const iv = Buffer.from(parts[0], 'hex');
  const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
  let decrypted = decipher.update(parts[1], 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

async function loadJson(file, fallback) {
  if (USE_SUPABASE_STORAGE) {
    const key = getStorageKey(file);
    const value = await supabaseGet(key);
    if (value == null) return fallback;
    if (file === TOKEN_PATH) {
      if (typeof value === 'string') {
        const content = TOKEN_ENCRYPTION_KEY ? decryptToken(value) : value;
        return JSON.parse(content);
      }
      return value;
    }
    return value;
  }

  if (!(await fileExists(file))) return fallback;
  try {
    const raw = await fsPromises.readFile(file, 'utf8');
    const content = file === TOKEN_PATH ? decryptToken(raw) : raw;
    return JSON.parse(content);
  } catch (e) {
    log('error', `Failed to parse ${file}`, { error: e.message });
    return fallback;
  }
}

async function saveJson(file, data) {
  if (USE_SUPABASE_STORAGE) {
    const key = getStorageKey(file);
    if (file === TOKEN_PATH) {
      const raw = JSON.stringify(data, null, 2);
      const content = TOKEN_ENCRYPTION_KEY ? encryptToken(raw) : raw;
      await supabaseSet(key, content);
      return;
    }
    await supabaseSet(key, data);
    return;
  }

  const raw = JSON.stringify(data, null, 2);
  const content = file === TOKEN_PATH ? encryptToken(raw) : raw;
  await fsPromises.writeFile(file, content);
}

async function loadAliases() {
  return loadJson(ALIASES_PATH, []);
}

async function saveAliases(list) {
  await saveJson(ALIASES_PATH, list);
}

async function loadDomains() {
  const domains = await loadJson(DOMAINS_PATH, []);
  if (domains.length) return domains;
  const now = new Date().toISOString();
  const defaults = [
    {
      name: 'selebungms.my.id',
      active: true,
      createdAt: now
    }
  ];
  await saveJson(DOMAINS_PATH, defaults);
  return defaults;
}

async function saveDomains(list) {
  await saveJson(DOMAINS_PATH, list);
}

async function loadLogs() {
  return loadJson(LOGS_PATH, []);
}

async function saveLogs(list) {
  await saveJson(LOGS_PATH, list);
}

async function loadAudit() {
  return loadJson(AUDIT_PATH, []);
}

async function saveAudit(list) {
  await saveJson(AUDIT_PATH, list);
}

// ========== VALIDATION ==========
const emailSchema = z
  .string()
  .email()
  .max(254)
  .refine((email) => {
    const [local, domain] = email.split('@');
    return local && local.length <= 64 && domain && domain.length <= 190;
  });

const domainSchema = z
  .string()
  .regex(/^[a-zA-Z0-9.-]+\.[A-Za-z]{2,}$/)
  .max(190);

function isValidEmail(address) {
  if (!address || typeof address !== 'string') return false;
  const trimmed = address.trim().toLowerCase();
  return emailSchema.safeParse(trimmed).success;
}

async function isAllowedDomain(domain) {
  const domains = await loadDomains();
  return domains.find((d) => d.name === domain && d.active);
}

async function auditLog(action, reqMeta = {}) {
  const audits = await loadAudit();
  const entry = {
    timestamp: new Date().toISOString(),
    action,
    ...reqMeta
  };
  audits.push(entry);
  const MAX_AUDIT = 1000;
  if (audits.length > MAX_AUDIT) audits.splice(0, audits.length - MAX_AUDIT);
  await saveAudit(audits);
  log('info', 'Audit log', entry);
}

// ========== CACHE ==========
const messageCache = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000;

function cacheGet(key) {
  const entry = messageCache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    messageCache.delete(key);
    return null;
  }
  return entry.value;
}

function cacheSet(key, value, ttl = CACHE_TTL_MS) {
  messageCache.set(key, { value, expiresAt: Date.now() + ttl });
}

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of messageCache.entries()) {
    if (entry.expiresAt < now) messageCache.delete(key);
  }
}, CACHE_TTL_MS).unref();

// ========== OAUTH STATE ==========
const AUTH_SCOPES = ['https://www.googleapis.com/auth/gmail.readonly'];
const AUTH_STATE_TTL_MS = 10 * 60 * 1000;
const pendingStates = new Map();

function createState() {
  const state = crypto.randomBytes(24).toString('hex');
  pendingStates.set(state, Date.now() + AUTH_STATE_TTL_MS);
  return state;
}

function consumeState(state) {
  const expiresAt = pendingStates.get(state);
  if (!expiresAt) return false;
  pendingStates.delete(state);
  return expiresAt >= Date.now();
}

setInterval(() => {
  const now = Date.now();
  for (const [state, exp] of pendingStates.entries()) {
    if (exp < now) pendingStates.delete(state);
  }
}, AUTH_STATE_TTL_MS).unref();

// ========== OAUTH CLIENT ==========
let oauthClientSingleton = null;

async function tokenExists() {
  if (USE_SUPABASE_STORAGE) {
    const key = getStorageKey(TOKEN_PATH);
    const value = await supabaseGet(key);
    return value != null;
  }
  return fileExists(TOKEN_PATH);
}

async function getOAuthClient() {
  if (oauthClientSingleton) return oauthClientSingleton;
  const client = new google.auth.OAuth2(
    env.GOOGLE_CLIENT_ID,
    env.GOOGLE_CLIENT_SECRET,
    env.GOOGLE_REDIRECT_URI
  );

  if (await tokenExists()) {
    try {
      const saved = await loadJson(TOKEN_PATH, null);
      if (saved) {
        client.setCredentials(saved);
        log('info', 'Loaded saved token');
      }
    } catch (e) {
      log('error', 'Failed to parse token file', { error: e.message });
    }
  }

  client.on('tokens', async (tokens) => {
    let current = {};
    if (await tokenExists()) {
      try {
        current = await loadJson(TOKEN_PATH, {});
      } catch (e) {
        log('error', 'Failed reading token on refresh', { error: e.message });
      }
    }
    const updated = { ...current, ...tokens };
    await saveJson(TOKEN_PATH, updated);
    log('info', 'Token refreshed and saved');
  });

  oauthClientSingleton = client;
  return client;
}

async function ensureToken() {
  if (!(await tokenExists())) {
    throw new HttpError(401, 'Not authenticated');
  }
  try {
    const tokens = await loadJson(TOKEN_PATH, null);
    if (!tokens) throw new Error('Invalid token content');
    const client = await getOAuthClient();
    client.setCredentials(tokens);
    return client;
  } catch (e) {
    log('error', 'Failed to read token', { error: e.message });
    throw new HttpError(500, 'Token file invalid');
  }
}

function requireAdmin(request) {
  const key = request.headers.get('x-admin-key');
  if (!key || key !== env.ADMIN_API_KEY) {
    throw new HttpError(401, 'Unauthorized');
  }
}

function decodeBase64Url(str = '') {
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}

function extractBody(payload) {
  let bodyHtml = '';
  let bodyText = '';

  function traverse(part) {
    if (!part) return;
    const data = part.body?.data ? decodeBase64Url(part.body.data) : '';
    if (part.mimeType === 'text/html') bodyHtml += data;
    if (part.mimeType === 'text/plain') bodyText += data;
    if (part.parts) part.parts.forEach(traverse);
  }

  traverse(payload);
  return { bodyHtml, bodyText };
}

async function touchLogs(msgs, alias) {
  if (!msgs || !msgs.length) return;
  const now = new Date().toISOString();
  const logs = await loadLogs();
  const indexById = new Map();
  logs.forEach((l, i) => indexById.set(l.id, i));

  msgs.forEach((m) => {
    const idx = indexById.get(m.id);
    if (idx != null) {
      logs[idx].lastSeenAt = now;
      logs[idx].alias = alias || logs[idx].alias || null;
    } else {
      logs.push({
        id: m.id,
        alias: alias || null,
        from: m.from || '',
        subject: m.subject || '',
        date: m.date || '',
        snippet: m.snippet || '',
        lastSeenAt: now
      });
    }
  });

  const MAX_LOGS = 500;
  if (logs.length > MAX_LOGS) {
    logs.sort((a, b) => new Date(b.lastSeenAt || 0) - new Date(a.lastSeenAt || 0));
    logs.length = MAX_LOGS;
  }

  await saveLogs(logs);
}

// ========== SERVICE METHODS ==========
async function generateAuthUrl() {
  const state = createState();
  const client = await getOAuthClient();
  const url = client.generateAuthUrl({
    access_type: 'offline',
    scope: AUTH_SCOPES,
    prompt: 'consent',
    state
  });
  return { url, state, expiresInMs: AUTH_STATE_TTL_MS };
}

async function exchangeCode(code, state) {
  if (!code) throw new HttpError(400, 'No code provided');
  // State validation optional (for development) - state bisa null
  if (state && !consumeState(state)) {
    log('warn', 'State validation failed but proceeding', { state });
  }
  try {
    const client = await getOAuthClient();
    const { tokens } = await client.getToken(code);
    client.setCredentials(tokens);
    await saveJson(TOKEN_PATH, tokens);
    log('info', 'Token obtained and saved successfully');
    return { ok: true };
  } catch (err) {
    log('error', 'Failed to get tokens', { error: err.message });
    throw new HttpError(500, 'Failed to get tokens');
  }
}

async function revokeToken() {
  if (!(await tokenExists())) {
    throw new HttpError(404, 'No token to revoke');
  }
  try {
    const client = await getOAuthClient();
    await client.revokeCredentials();
    if (!USE_SUPABASE_STORAGE) {
      await fsPromises.unlink(TOKEN_PATH);
    } else {
      await supabaseSet(getStorageKey(TOKEN_PATH), null);
    }
    await auditLog('token_revoked');
    return { ok: true };
  } catch (err) {
    log('error', 'Failed to revoke token', { error: err.message });
    throw new HttpError(500, 'Failed to revoke token');
  }
}

async function health() {
  return {
    ok: true,
    hasToken: await tokenExists(),
    allowedOrigins: ALLOWED_ORIGINS,
    maxMessages: MAX_MESSAGES,
    cacheSize: messageCache.size
  };
}

async function tokenHealth() {
  const client = await ensureToken();
  const gmail = google.gmail({ version: 'v1', auth: client });
  const start = Date.now();
  await gmail.users.getProfile({ userId: 'me' });
  return { ok: true, tokenValid: true, latencyMs: Date.now() - start };
}

async function listMessages(alias) {
  const client = await ensureToken();
  const gmail = google.gmail({ version: 'v1', auth: client });
  const trimmedAlias = (alias || '').trim().toLowerCase();

  const listOptions = {
    userId: 'me',
    maxResults: MAX_MESSAGES,
    labelIds: ['INBOX']
  };

  if (trimmedAlias) {
    if (!isValidEmail(trimmedAlias)) throw new HttpError(400, 'Invalid alias address');
    const domain = trimmedAlias.split('@')[1];
    if (!(await isAllowedDomain(domain))) throw new HttpError(400, 'Domain not allowed');
    listOptions.q = `to:${trimmedAlias}`;

    const now = new Date().toISOString();
    const aliases = await loadAliases();
    const found = aliases.find((a) => a.address === trimmedAlias);
    if (found) {
      found.lastUsedAt = now;
      found.hits = (found.hits || 0) + 1;
      await saveAliases(aliases);
    }
  }

  const listRes = await gmail.users.messages.list(listOptions);
  const messages = listRes.data.messages || [];

  const results = await Promise.all(
    messages.map(async (msg) => {
      const cached = cacheGet(`msg:${msg.id}`);
      if (cached) return cached;

      const msgRes = await gmail.users.messages.get({
        userId: 'me',
        id: msg.id,
        format: 'metadata',
        metadataHeaders: ['Subject', 'From', 'Date', 'To']
      });

      const headers = msgRes.data.payload.headers || [];
      const getHeader = (name) =>
        headers.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value || '';

      const result = {
        id: msg.id,
        subject: getHeader('Subject'),
        from: getHeader('From'),
        to: getHeader('To'),
        date: getHeader('Date'),
        snippet: msgRes.data.snippet || ''
      };

      cacheSet(`msg:${msg.id}`, result);
      return result;
    })
  );

  await touchLogs(results, trimmedAlias || null);
  return { messages: results };
}

async function getMessageDetail(id) {
  if (!id) throw new HttpError(400, 'Missing message id');
  const cached = cacheGet(`detail:${id}`);
  if (cached) return cached;

  const client = await ensureToken();
  const gmail = google.gmail({ version: 'v1', auth: client });
  const msgRes = await gmail.users.messages.get({
    userId: 'me',
    id,
    format: 'full'
  });

  const headers = msgRes.data.payload.headers || [];
  const getHeader = (name) =>
    headers.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value || '';

  const { bodyHtml, bodyText } = extractBody(msgRes.data.payload);

  const result = {
    id,
    subject: getHeader('Subject'),
    from: getHeader('From'),
    date: getHeader('Date'),
    snippet: msgRes.data.snippet,
    bodyHtml,
    bodyText
  };

  cacheSet(`detail:${id}`, result);
  return result;
}

async function registerAlias(address) {
  const addr = (address || '').trim().toLowerCase();
  if (!isValidEmail(addr)) throw new HttpError(400, 'Invalid address');
  const domain = addr.split('@')[1];
  if (!(await isAllowedDomain(domain))) throw new HttpError(400, 'Domain not allowed');

  const now = new Date().toISOString();
  const aliases = await loadAliases();
  const existing = aliases.find((a) => a.address === addr);
  if (existing) {
    existing.lastUsedAt = now;
    existing.hits = (existing.hits || 0) + 1;
  } else {
    aliases.push({ address: addr, createdAt: now, lastUsedAt: now, hits: 1, active: true });
  }
  await saveAliases(aliases);
  return { ok: true };
}

async function adminStats() {
  const aliases = await loadAliases();
  const domains = await loadDomains();
  const total = aliases.length;
  const totalHits = aliases.reduce((sum, a) => sum + (a.hits || 0), 0);
  return {
    totalAliases: total,
    totalHits,
    lastAliasCreatedAt: aliases[total - 1]?.createdAt || null,
    totalDomains: domains.length
  };
}

async function adminAliases() {
  return { aliases: await loadAliases() };
}

async function deleteAlias(address) {
  const addrParam = decodeURIComponent(address || '').toLowerCase();
  const aliases = await loadAliases();
  const filtered = aliases.filter((a) => a.address !== addrParam);
  await saveAliases(filtered);
  await auditLog('alias_deleted', { address: addrParam });
  return { removed: aliases.length - filtered.length };
}

async function adminDomains() {
  return { domains: await loadDomains() };
}

async function publicDomains() {
  const domains = (await loadDomains()).filter((d) => d.active);
  return { domains };
}

async function addDomain(name) {
  const trimmed = (name || '').trim().toLowerCase();
  const validation = domainSchema.safeParse(trimmed);
  if (!validation.success) throw new HttpError(400, 'Invalid domain name');

  const domains = await loadDomains();
  if (domains.find((d) => d.name === trimmed)) throw new HttpError(400, 'Domain already exists');

  const now = new Date().toISOString();
  domains.push({ name: trimmed, active: true, createdAt: now });
  await saveDomains(domains);
  await auditLog('domain_added', { domain: trimmed });
  return { ok: true };
}

async function updateDomain(name, body) {
  const nameParam = decodeURIComponent(name || '').toLowerCase();
  const domains = await loadDomains();
  const target = domains.find((d) => d.name === nameParam);
  if (!target) throw new HttpError(404, 'Domain not found');
  if (typeof body?.active === 'boolean') target.active = body.active;
  await saveDomains(domains);
  return { ok: true, domain: target };
}

async function deleteDomain(name) {
  const nameParam = decodeURIComponent(name || '').toLowerCase();
  const domains = await loadDomains();
  const filtered = domains.filter((d) => d.name !== nameParam);
  await saveDomains(filtered);
  await auditLog('domain_deleted', { domain: nameParam });
  return { removed: domains.length - filtered.length };
}

async function adminLogs(limit, aliasFilter) {
  const normalizedLimit = Math.min(parseInt(limit || '50', 10) || 50, 200);
  const filter = (aliasFilter || '').toLowerCase().trim();
  let logs = await loadLogs();
  if (filter) logs = logs.filter((l) => (l.alias || '').toLowerCase() === filter);
  logs.sort((a, b) => new Date(b.lastSeenAt || 0) - new Date(a.lastSeenAt || 0));
  logs = logs.slice(0, normalizedLimit);
  return { logs };
}

async function clearLogs() {
  await auditLog('logs_cleared');
  await saveLogs([]);
  return { cleared: true };
}

export {
  HttpError,
  env,
  health,
  tokenHealth,
  generateAuthUrl,
  exchangeCode,
  revokeToken,
  listMessages,
  getMessageDetail,
  registerAlias,
  adminStats,
  adminAliases,
  deleteAlias,
  adminDomains,
  publicDomains,
  addDomain,
  updateDomain,
  deleteDomain,
  adminLogs,
  clearLogs,
  requireAdmin
};
