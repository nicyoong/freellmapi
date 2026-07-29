import { Router } from 'express';
import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import multer from 'multer';
import path from 'path';
import { getDb } from '../db/index.js';
import { resolveProvider, getAllProviders } from '../providers/index.js';
import { encrypt, decrypt, maskKey } from '../lib/crypto.js';
import { parseKeysFromFile, stripJsoncComments, stripTrailingCommas } from '../lib/key-parser.js';
import { assessProviderUrl } from '../lib/url-guard.js';
import { ensureModelInProfiles } from '../services/profile-models.js';
import { getActiveCooldownsForKeys, clearCooldownsForKey } from '../services/ratelimit.js';
import { resolveCustomEndpointKey, customEndpointKeyIds, customEndpointIdForKey, siblingEndpointKeyId } from '../services/custom-endpoint.js';
import { customModelSeed } from '../services/custom-model-seed.js';
import { discoverEndpointModels, ModelDiscoveryError } from '../services/model-discovery.js';

export const keysRouter = Router();

// Active providers — must match providers/index.ts registrations + shared/types.ts Platform.
// Moonshot and MiniMax direct integrations were dropped in V4. HuggingFace
// was dropped in V4 and re-added in V13 via the router.huggingface.co route.
// SambaNova was dropped in V23 (free tier permanently retired).
const PLATFORMS = [
  'google', 'groq', 'cerebras', 'nvidia', 'mistral',
  'openrouter', 'github', 'cohere', 'cloudflare', 'zhipu', 'ollama',
  'kilo', 'pollinations', 'llm7', 'huggingface', 'opencode', 'ovh', 'agnes', 'reka', 'siliconflow',
  'routeway', 'bazaarlink', 'ainative', 'aion', 'requesty', 'navy', 'nara', 'sealion', 'modelscope', 'aihorde', 'custom',
] as const;

const ALLOWED_IMPORT_EXTENSIONS = new Set(['.env', '.json', '.jsonc', '.md', '.txt', '.csv']);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 10 },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_IMPORT_EXTENSIONS.has(ext)) {
      cb(new Error('Unsupported file type'));
      return;
    }
    cb(null, true);
  },
});

// `key` is optional so keyless providers (Kilo's anonymous gateway) can be added
// without one; the handler enforces a non-empty key for everyone else.
const addKeySchema = z.object({
  platform: z.enum(PLATFORMS),
  key: z.string().optional(),
  label: z.string().optional(),
});

const updateKeySchema = z.object({
  enabled: z.boolean().optional(),
  label: z.string().optional(),
}).refine(data => data.enabled !== undefined || data.label !== undefined, {
  message: 'At least one of enabled or label must be provided',
});

const importKeySchema = z.object({
  keyName: z.string().optional(),
  keyValue: z.string().min(1),
  platform: z.enum(PLATFORMS),
});

function handleUploadError(err: any, res: Response, next: NextFunction): boolean {
  if (!err) return false;
  if (err.code === 'LIMIT_FILE_SIZE') {
    res.status(413).json({ error: { message: 'File too large. Maximum size is 5MB' } });
    return true;
  }
  if (err.code === 'LIMIT_FILE_COUNT') {
    res.status(413).json({ error: { message: 'Too many files. Maximum is 10' } });
    return true;
  }
  if (err.message?.includes('Unsupported file type')) {
    res.status(400).json({ error: { message: 'Unsupported file type' } });
    return true;
  }
  next(err);
  return true;
}

function parseUpload(file: Express.Multer.File) {
  const content = file.buffer.toString('utf8');
  if (!content.trim()) {
    throw Object.assign(new Error('File contains no data'), { status: 400 });
  }

  if (/\.jsonc?$/i.test(file.originalname)) {
    try {
      JSON.parse(stripTrailingCommas(stripJsoncComments(content)));
    } catch {
      throw Object.assign(new Error('Invalid JSON format'), { status: 400 });
    }
  }

  return parseKeysFromFile(content, file.originalname);
}

function splitRawKey(rawKey: string) {
  const eqIndex = rawKey.indexOf('=');
  return {
    keyName: eqIndex === -1 ? rawKey : rawKey.slice(0, eqIndex),
    keyValue: eqIndex === -1 ? '' : rawKey.slice(eqIndex + 1),
  };
}

function insertImportedKey(platform: (typeof PLATFORMS)[number], keyName: string, keyValue: string) {
  if (platform === 'custom') {
    throw new Error('Custom providers must be added with a base URL');
  }
  if (!resolveProvider(platform)) {
    throw new Error(`Unsupported platform: ${platform}`);
  }

  const db = getDb();
  const { encrypted, iv, authTag } = encrypt(keyValue.trim());
  db.prepare(`
    INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled)
    VALUES (?, ?, ?, ?, ?, 'unknown', 1)
  `).run(platform, keyName, encrypted, iv, authTag);
}

// Count enabled catalog models for a platform. Used to warn when a key is
// added for a provider that has zero models in the operator's current catalog
// tier — the Agnes case (#438): the provider is registered and selectable, but
// its models ship in the premium/live catalog and only appear for free-tier
// installs once they age into the monthly catalog, so a fresh install adds the
// key and silently sees nothing.
function enabledModelCount(platform: string): number {
  const db = getDb();
  const row = db.prepare(
    'SELECT COUNT(*) AS c FROM models WHERE platform = ? AND enabled = 1',
  ).get(platform) as { c: number };
  return row.c;
}

// Non-null when the just-added key has no usable models yet, so the client can
// explain the silence instead of leaving the user staring at an empty list.
function noModelsNotice(platform: string): string | undefined {
  if (enabledModelCount(platform) > 0) return undefined;
  return (
    `Key saved, but no ${platform} models are in your current catalog yet. ` +
    `Newer providers are published to the premium catalog first and appear ` +
    `for free-tier installs once they age into the monthly catalog. Add a ` +
    `Premium license key to use them now, or add ${platform} as a custom ` +
    `OpenAI-compatible provider with its base URL.`
  );
}

// Provider checklist (#543): every registered provider with whether the user
// has added at least one key yet, so the dashboard can show what's still
// missing without enumerating the whole list by hand. `custom` is excluded —
// it's a per-key user-defined placeholder, not a fixed free-tier provider to
// "check off".
keysRouter.get('/providers', (_req: Request, res: Response) => {
  const db = getDb();
  const countRows = db.prepare(`
    SELECT
      platform,
      COUNT(*) AS total_keys,
      SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) AS enabled_keys
    FROM api_keys
    GROUP BY platform
  `).all() as Array<{ platform: string; total_keys: number; enabled_keys: number }>;
  const countsByPlatform = new Map(countRows.map(r => [r.platform, r]));

  const providers = getAllProviders()
    .filter(p => p.platform !== 'custom')
    .map(p => {
      const counts = countsByPlatform.get(p.platform);
      const keyCount = counts?.total_keys ?? 0;
      return {
        platform: p.platform,
        name: p.name,
        keyless: p.keyless,
        configured: keyCount > 0,
        keyCount,
        enabledKeyCount: counts?.enabled_keys ?? 0,
      };
    })
    .sort((a, b) => a.name.localeCompare(b.name));

  const configured = providers.filter(p => p.configured).length;
  res.json({
    providers,
    summary: {
      total: providers.length,
      configured,
      unconfigured: providers.length - configured,
    },
  });
});

// List all keys (masked)
keysRouter.get('/', (_req: Request, res: Response) => {
  const db = getDb();
  const rows = db.prepare('SELECT * FROM api_keys ORDER BY created_at DESC').all() as any[];

  const customModels = [
    ...db.prepare(`
      SELECT key_id, id, 'chat' AS kind, model_id, display_name, NULL AS family
        FROM models
       WHERE platform = 'custom' AND key_id IS NOT NULL
    `).all() as any[],
    ...db.prepare(`
      SELECT key_id, id, 'embedding' AS kind, model_id, display_name, family
        FROM embedding_models
       WHERE platform = 'custom' AND key_id IS NOT NULL
    `).all() as any[],
    ...db.prepare(`
      SELECT key_id, id, modality AS kind, model_id, display_name, NULL AS family
        FROM media_models
       WHERE platform = 'custom' AND key_id IS NOT NULL
    `).all() as any[],
  ];
  // Models are grouped by ENDPOINT, not by key row: an endpoint can hold
  // several credentials (#619) while each model binds to just one of them, and
  // every one of those keys serves the endpoint's whole model list.
  const endpointOfKey = new Map<number, string>();
  for (const row of rows) {
    if (row.platform === 'custom' && row.base_url) endpointOfKey.set(Number(row.id), row.base_url);
  }
  const endpointOf = (keyId: number) => endpointOfKey.get(keyId) ?? `key:${keyId}`;

  const modelsByEndpoint = new Map<string, any[]>();
  for (const m of customModels) {
    const keyId = Number(m.key_id);
    if (!Number.isInteger(keyId)) continue;
    const list = modelsByEndpoint.get(endpointOf(keyId)) ?? [];
    list.push({
      id: m.id,
      kind: m.kind,
      modelId: m.model_id,
      displayName: m.display_name,
      family: m.family ?? null,
    });
    modelsByEndpoint.set(endpointOf(keyId), list);
  }
  for (const list of modelsByEndpoint.values()) {
    list.sort((a, b) => {
      const ka = ['chat', 'embedding', 'image', 'audio'].indexOf(a.kind);
      const kb = ['chat', 'embedding', 'image', 'audio'].indexOf(b.kind);
      return (ka - kb) || String(a.displayName).localeCompare(String(b.displayName));
    });
  }

  // A cooling-down key reads as healthy and enabled while the router skips it,
  // so surface the cooldowns that explain the idleness. (#P0-7)
  const cooldownsByKeyId = getActiveCooldownsForKeys(rows.map(row => Number(row.id)));

  const keys = rows.map(row => {
    let maskedKey = '****';
    try {
      const realKey = decrypt(row.encrypted_key, row.iv, row.auth_tag);
      maskedKey = maskKey(realKey);
    } catch {
      maskedKey = '[decrypt failed]';
    }
    const cooldowns = cooldownsByKeyId.get(Number(row.id)) ?? [];
    return {
      id: row.id,
      platform: row.platform,
      label: row.label,
      maskedKey,
      baseUrl: row.base_url ?? null,
      status: row.status,
      enabled: row.enabled === 1,
      keyless: resolveProvider(row.platform)?.keyless === true,
      createdAt: row.created_at,
      lastCheckedAt: row.last_checked_at,
      lastHealthError: row.last_health_error ?? null,
      models: row.platform === 'custom' ? (modelsByEndpoint.get(endpointOf(Number(row.id))) ?? []) : undefined,
      cooldowns: cooldowns.map(c => ({
        modelId: c.modelId,
        expiresAtMs: c.expiresAtMs,
        remainingMs: c.remainingMs,
      })),
    };
  });

  res.json(keys);
});

// Clear every active cooldown for one key. An escalated cooldown can bench a key
// for up to 24h from a single bad window; once the operator has fixed the cause
// there is otherwise no way back short of restarting and waiting it out.
keysRouter.delete('/:id/cooldowns', (req: Request, res: Response) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) {
    res.status(400).json({ error: 'Invalid key id' });
    return;
  }

  const db = getDb();
  const exists = db.prepare('SELECT 1 FROM api_keys WHERE id = ?').get(id);
  if (!exists) {
    res.status(404).json({ error: 'Key not found' });
    return;
  }

  const cleared = clearCooldownsForKey(id);
  res.json({ cleared });
});

// Export keys — returns plaintext keys in the requested format.
// GET /api/keys/export?format=json|env|csv&healthy=true
// The response is the raw file download (Content-Type varies by format).
keysRouter.get('/export', (req: Request, res: Response) => {
  const db = getDb();
  const format = (req.query.format as string) ?? 'json';
  const healthyOnly = req.query.healthy === 'true';

  let whereClause = '';
  if (healthyOnly) {
    whereClause = "WHERE status = 'healthy'";
  }

  const rows = db.prepare(`SELECT * FROM api_keys ${whereClause} ORDER BY platform, created_at ASC`).all() as any[];

  // Decrypt and filter — only export keys with a real value
  const decryptedKeys = rows
    .map(row => {
      let key = '';
      try {
        key = decrypt(row.encrypted_key, row.iv, row.auth_tag);
      } catch {
        key = '';
      }
      return {
        platform: row.platform,
        key,
        label: row.label || '',
        baseUrl: row.base_url || undefined,
      };
    })
    .filter(k => {
      const v = k.key.trim();
      return v.length > 0 && v !== 'no-key';
    });

  if (decryptedKeys.length === 0) {
    res.status(404).json({ error: { message: 'No keys to export' } });
    return;
  }

  if (format === 'env') {
    // .env format: GOOGLE_KEY=xxx\nGROQ_KEY=yyy
    const lines = decryptedKeys.map(k => {
      const envKey = `${k.platform.toUpperCase()}_KEY=${k.key}`;
      return k.label ? `# ${k.label}\n${envKey}` : envKey;
    });
    const content = lines.join('\n\n') + '\n';
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="freellmapi-keys.env"');
    res.send(content);
    return;
  }

  if (format === 'csv') {
    // CSV format: platform,key,label
    const escCsv = (v: string) => `"${v.replace(/"/g, '""')}"`;
    // CSV formula-injection guard: a spreadsheet treats a cell that starts with
    // =, +, -, @, tab or CR as a live formula, so a label like `=HYPERLINK(...)`
    // would execute on open. Prefix such cells with a single quote to force them
    // to be read as text. Applied only to free-text fields the user controls
    // (labels); the key value must round-trip verbatim for re-import, and the
    // platform is one of our own fixed enum values.
    const neutralize = (v: string) => (/^[=+\-@\t\r]/.test(v) ? `'${v}` : v);
    const header = 'platform,key,label';
    const lines = decryptedKeys.map(k =>
      [escCsv(k.platform), escCsv(k.key), escCsv(neutralize(k.label))].join(',')
    );
    const content = [header, ...lines].join('\n') + '\n';
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="freellmapi-keys.csv"');
    res.send(content);
    return;
  }

  // Default: JSON format (round-trip safe — can be imported directly)
  const jsonExport = {
    version: 1,
    exportedAt: new Date().toISOString(),
    source: 'freellmapi',
    keys: decryptedKeys,
  };
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="freellmapi-keys.json"');
  res.json(jsonExport);
});

// Add a key
keysRouter.post('/', (req: Request, res: Response) => {
  const parsed = addKeySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: { message: parsed.error.errors.map(e => e.message).join(', ') } });
    return;
  }

  const { platform, label } = parsed.data;
  const isKeyless = resolveProvider(platform)?.keyless === true;
  const rawKey = parsed.data.key?.trim() ?? '';

  if (!isKeyless && !rawKey) {
    res.status(400).json({ error: { message: 'key is required' } });
    return;
  }

  // Keyless providers (Kilo anon) store a sentinel so routing sees the platform
  // as configured; the provider omits the auth header on outgoing calls.
  const keyToStore = isKeyless ? (rawKey || 'no-key') : rawKey;

  const db = getDb();

  // A keyless provider needs only one sentinel row — re-enable an existing one
  // instead of piling up duplicates each time the user clicks "Add".
  if (isKeyless) {
    const existing = db.prepare('SELECT id FROM api_keys WHERE platform = ? LIMIT 1').get(platform) as { id: number } | undefined;
    if (existing) {
      db.prepare("UPDATE api_keys SET enabled = 1, status = 'unknown' WHERE id = ?").run(existing.id);
      res.status(200).json({
        id: existing.id,
        platform,
        label: label ?? '',
        maskedKey: maskKey(keyToStore),
        status: 'unknown',
        enabled: true,
        modelsAvailable: enabledModelCount(platform),
        notice: noModelsNotice(platform),
      });
      return;
    }
  }

  const { encrypted, iv, authTag } = encrypt(keyToStore);
  const result = db.prepare(`
    INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled)
    VALUES (?, ?, ?, ?, ?, 'unknown', 1)
  `).run(platform, label ?? '', encrypted, iv, authTag);

  res.status(201).json({
    id: result.lastInsertRowid,
    platform,
    label: label ?? '',
    maskedKey: maskKey(keyToStore),
    status: 'unknown',
    enabled: true,
    modelsAvailable: enabledModelCount(platform),
    notice: noModelsNotice(platform),
  });
});

// ── Custom OpenAI-compatible providers (#117, #212) ───────────────────────
// User-configured endpoints (llama.cpp / LM Studio / vLLM / Ollama / any
// OpenAI-compatible base_url). Each DISTINCT base_url gets its own 'custom'
// api_keys row, and every registered model binds to its endpoint's key via
// models.key_id — so several custom providers coexist without overwriting
// each other (#212). Re-submitting an existing base_url updates its key/label;
// re-registering an existing model id re-binds it to the submitted endpoint.
// A model can be given as a bare id ("qwen3:4b") or as {model, displayName}.
// `model`/`displayName` (singular) stay supported for older clients; `models`
// (plural) lets one submit bind several model ids to the same endpoint. (#281)
// A custom model can declare its capabilities at registration. `supportsTools`
// defaults to 1 (modern OpenAI-compatible servers — Ollama, vLLM, LM Studio —
// all emit tool calls), `supportsVision` defaults to 0 unless declared. Leaving
// a flag unset keeps the DB default on insert and preserves the stored value on
// re-registration, so a capability the user later toggled isn't clobbered. (#470)
const modelEntrySchema = z.union([
  z.string().min(1),
  z.object({
    model: z.string().min(1),
    displayName: z.string().optional(),
    supportsTools: z.boolean().optional(),
    supportsVision: z.boolean().optional(),
  }),
]);
// `baseUrl` and `keyId` are both optional but at least one is required: the
// bulk registration that follows model discovery (#488) already holds the
// api_keys row it fetched the list with, and naming that row keeps the new
// models on the same credential of the endpoint's pool (#619/#640).
const customProviderSchema = z.object({
  baseUrl: z.string().url('baseUrl must be a valid URL').optional(),
  keyId: z.number().int().positive().optional(),
  model: z.string().optional(),
  models: z.array(modelEntrySchema).optional(),
  displayName: z.string().optional(),
  apiKey: z.string().optional(),
  label: z.string().optional(),
  // Top-level defaults applied to every model in this submit; a per-entry flag
  // (object form) overrides them for that one model.
  supportsTools: z.boolean().optional(),
  supportsVision: z.boolean().optional(),
}).refine(
  d => (d.model && d.model.trim().length > 0) || (d.models && d.models.length > 0),
  { message: 'model or models is required' },
).refine(
  d => d.baseUrl !== undefined || d.keyId !== undefined,
  { message: 'baseUrl or keyId is required' },
);

const normalizeBaseUrl = (raw: string) => raw.trim().replace(/\/+$/, '');

interface CustomEndpointRef {
  baseUrl: string;
  /** The api_keys row this endpoint is already stored under, or null when the
   *  endpoint has never been registered. */
  keyId: number | null;
  /** Plaintext of that row's credential, when there is one. */
  storedKey: string | null;
}

/**
 * Turn a `{ keyId?, baseUrl? }` reference into the endpoint it names. A keyId
 * is the stronger reference (it identifies one credential of the pool); a bare
 * baseUrl falls back to the endpoint's first stored key, which is how the rest
 * of the custom-endpoint machinery addresses an endpoint. Throws a
 * `{ status, message }` for a reference that names nothing usable.
 */
function resolveEndpointRef(ref: { keyId?: number; baseUrl?: string }): CustomEndpointRef {
  const db = getDb();
  const requestedBaseUrl = ref.baseUrl === undefined ? undefined : normalizeBaseUrl(ref.baseUrl);

  if (ref.keyId !== undefined) {
    const row = db.prepare('SELECT id, platform, base_url, encrypted_key, iv, auth_tag FROM api_keys WHERE id = ?')
      .get(ref.keyId) as { id: number; platform: string; base_url: string | null; encrypted_key: string; iv: string; auth_tag: string } | undefined;
    if (!row || row.platform !== 'custom' || !row.base_url) {
      throw Object.assign(new Error('keyId does not name a custom endpoint'), { status: 400 });
    }
    if (requestedBaseUrl !== undefined && requestedBaseUrl !== row.base_url) {
      throw Object.assign(new Error('baseUrl does not match the endpoint keyId belongs to'), { status: 400 });
    }
    let storedKey: string | null = null;
    try {
      storedKey = decrypt(row.encrypted_key, row.iv, row.auth_tag);
    } catch { /* an undecryptable row still names the endpoint */ }
    return { baseUrl: row.base_url, keyId: row.id, storedKey };
  }

  if (!requestedBaseUrl) {
    throw Object.assign(new Error('baseUrl or keyId is required'), { status: 400 });
  }

  // Any key of this base_url serves the whole endpoint (#619), so the first one
  // is as good a representative as any.
  const rows = db.prepare(`
    SELECT id, encrypted_key, iv, auth_tag FROM api_keys
     WHERE platform = 'custom' AND base_url = ? ORDER BY id
  `).all(requestedBaseUrl) as Array<{ id: number; encrypted_key: string; iv: string; auth_tag: string }>;
  for (const row of rows) {
    try {
      return { baseUrl: requestedBaseUrl, keyId: row.id, storedKey: decrypt(row.encrypted_key, row.iv, row.auth_tag) };
    } catch { /* try the next credential */ }
  }
  return { baseUrl: requestedBaseUrl, keyId: rows[0]?.id ?? null, storedKey: null };
}

// SSRF guard (#440): a base_url is the one user-controlled outbound target.
// Cloud metadata / link-local addresses are rejected outright; private ranges
// too when FREEAPI_BLOCK_PRIVATE_PROVIDER_URLS is set. Re-checked at request
// time in proxyFetch for URLs already in the DB.
async function rejectUnsafeBaseUrl(baseUrl: string, res: Response): Promise<boolean> {
  const verdict = await assessProviderUrl(baseUrl);
  if (verdict.allowed) return false;
  res.status(400).json({ error: { message: `baseUrl rejected: ${verdict.reason}` } });
  return true;
}

// Ask a configured custom endpoint what models it currently serves (#488).
// Relays add and drop models weekly, so re-typing the ids by hand goes stale
// immediately. This reads ONLY the operator's own base_url with the operator's
// own key — it never reads or refreshes the published provider catalog. Nothing
// is written: the picked ids come back through POST /custom to be registered.
const discoverModelsSchema = z.object({
  baseUrl: z.string().url('baseUrl must be a valid URL').optional(),
  keyId: z.number().int().positive().optional(),
  // Lets the Keys page fetch a list for an endpoint the user is still typing in,
  // before it has been saved. Falls back to the endpoint's stored credential.
  apiKey: z.string().optional(),
}).refine(
  d => d.baseUrl !== undefined || d.keyId !== undefined,
  { message: 'baseUrl or keyId is required' },
);

keysRouter.post('/custom/discover-models', async (req: Request, res: Response) => {
  const parsed = discoverModelsSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: { message: parsed.error.errors.map(e => e.message).join(', ') } });
    return;
  }

  let endpoint: CustomEndpointRef;
  try {
    endpoint = resolveEndpointRef(parsed.data);
  } catch (err: any) {
    res.status(err.status ?? 400).json({ error: { message: err.message } });
    return;
  }

  if (await rejectUnsafeBaseUrl(endpoint.baseUrl, res)) return;

  // A submitted key wins (the user may be rotating it); otherwise use what the
  // endpoint already has. Local servers with auth off keep the 'no-key'
  // sentinel, which the bearer header carries harmlessly.
  const apiKey = parsed.data.apiKey?.trim() || endpoint.storedKey || 'no-key';

  try {
    const discovered = await discoverEndpointModels(endpoint.baseUrl, apiKey);

    // "Already registered" means bound to THIS endpoint — any key of the pool
    // counts, since they all serve the same model list (#619).
    const db = getDb();
    const registeredIds = new Set<string>();
    if (endpoint.keyId != null) {
      const poolIds = [...customEndpointKeyIds(db, endpoint.keyId)];
      const placeholders = poolIds.map(() => '?').join(', ');
      const rows = db.prepare(
        `SELECT model_id FROM models WHERE platform = 'custom' AND key_id IN (${placeholders})`,
      ).all(...poolIds) as { model_id: string }[];
      for (const row of rows) registeredIds.add(row.model_id);
    }

    const models = discovered.map(m => ({ ...m, registered: registeredIds.has(m.id) }));
    res.json({
      baseUrl: endpoint.baseUrl,
      keyId: endpoint.keyId,
      models,
      total: models.length,
      registeredCount: models.filter(m => m.registered).length,
    });
  } catch (err: any) {
    if (err instanceof ModelDiscoveryError) {
      res.status(err.status).json({ error: { message: err.message } });
      return;
    }
    res.status(502).json({ error: { message: `Model discovery failed: ${err?.message ?? 'unknown error'}` } });
  }
});

keysRouter.post('/custom', async (req: Request, res: Response) => {
  const parsed = customProviderSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: { message: parsed.error.errors.map(e => e.message).join(', ') } });
    return;
  }

  let endpoint: CustomEndpointRef;
  try {
    endpoint = resolveEndpointRef(parsed.data);
  } catch (err: any) {
    res.status(err.status ?? 400).json({ error: { message: err.message } });
    return;
  }
  const baseUrl = endpoint.baseUrl;

  if (await rejectUnsafeBaseUrl(baseUrl, res)) return;

  // Local servers often need no key; keep a sentinel so there's always a bearer.
  const providedKey = parsed.data.apiKey?.trim() || undefined;
  const label = parsed.data.label?.trim() || undefined;

  // Flatten singular + plural inputs into one list, dedupe by model id, drop
  // blanks. The singular `displayName` only applies to a lone `model` (it can't
  // sensibly fan out across many ids). Capability flags resolve per-entry first,
  // then fall back to the submit-level defaults, then to undefined (DB default).
  const topTools = parsed.data.supportsTools;
  const topVision = parsed.data.supportsVision;
  const entries: { modelId: string; displayName: string; supportsTools?: boolean; supportsVision?: boolean }[] = [];
  const seen = new Set<string>();
  const addEntry = (rawId: string, rawDisplay?: string, tools?: boolean, vision?: boolean) => {
    const modelId = rawId.trim();
    if (!modelId || seen.has(modelId)) return;
    seen.add(modelId);
    entries.push({
      modelId,
      displayName: (rawDisplay?.trim() || modelId),
      supportsTools: tools ?? topTools,
      supportsVision: vision ?? topVision,
    });
  };
  if (parsed.data.model?.trim()) addEntry(parsed.data.model, parsed.data.displayName);
  for (const m of parsed.data.models ?? []) {
    if (typeof m === 'string') addEntry(m);
    else addEntry(m.model, m.displayName, m.supportsTools, m.supportsVision);
  }

  if (entries.length === 0) {
    res.status(400).json({ error: { message: 'model or models is required' } });
    return;
  }

  const db = getDb();
  const upsert = db.transaction(() => {
    // Key rows are matched on (base_url, secret): a new secret for a known
    // endpoint is a SECOND credential for it, not a replacement (#619), and a
    // new base_url is a separate provider (#212). Re-submitting with a blank
    // key preserves the stored one. A submitted keyId pins WHICH credential of
    // the pool the new models bind to (#488 bulk registration).
    const { keyId, storedKey: storedKeyForMask } = resolveCustomEndpointKey(
      db, baseUrl, providedKey, label, endpoint.keyId ?? undefined,
    );
    const endpointKeyIds = customEndpointKeyIds(db, keyId);
    const customEndpointId = customEndpointIdForKey(db, keyId);
    if (customEndpointId == null) throw new Error('Custom endpoint identity is unavailable for this key');
    // Unknown ≠ worst: seed the routing ranks at the catalog median so a new
    // custom model is explored instead of buried at intelligence 0 (#488).
    const seed = customModelSeed(db);

    const registered: { modelDbId: number; model: string; displayName: string; supportsTools: boolean; supportsVision: boolean; created: boolean }[] = [];
    for (const { modelId, displayName, supportsTools, supportsVision } of entries) {
      // Register each model bound to THIS endpoint's key. Custom models carry no
      // rate limits and sort last in the intelligence preset (size_label tier).
      // Re-registering an existing model id re-binds it to the submitted
      // ENDPOINT (model ids are unique per platform, so one id can't live on two
      // endpoints at once) — but a model already on this endpoint keeps the key
      // it has, so adding a second credential doesn't silently re-bind it (#619).
      // Capability flags: an unset flag binds NULL so COALESCE picks the insert
      // default (tools 1, vision 0) on a new row and preserves the existing
      // value on re-registration. (#470)
      const bound = db.prepare("SELECT key_id FROM models WHERE platform = 'custom' AND custom_endpoint_id = ? AND model_id = ?")
        .get(customEndpointId, modelId) as { key_id: number | null } | undefined;
      const created = bound === undefined;
      const bindKeyId = bound?.key_id != null && endpointKeyIds.has(bound.key_id) ? bound.key_id : keyId;
      const toolsParam = supportsTools === undefined ? null : (supportsTools ? 1 : 0);
      const visionParam = supportsVision === undefined ? null : (supportsVision ? 1 : 0);
      // The seed applies on INSERT only: DO UPDATE deliberately leaves the rank
      // columns alone so re-registering a model (or bulk-adding alongside it)
      // never rewrites ranks the operator has since tuned by hand.
      db.prepare(`
        INSERT INTO models
          (platform, model_id, display_name, intelligence_rank, speed_rank, size_label,
           rpm_limit, rpd_limit, tpm_limit, tpd_limit, monthly_token_budget, context_window, enabled, key_id,
           supports_tools, supports_vision, source, custom_endpoint_id)
        VALUES ('custom', @modelId, @displayName, @intelligenceRank, @speedRank, @sizeLabel,
           NULL, NULL, NULL, NULL, '', NULL, 1, @keyId,
           COALESCE(@tools, 1), COALESCE(@vision, 0), 'user', @customEndpointId)
        ON CONFLICT DO UPDATE SET
          display_name = excluded.display_name,
          key_id = excluded.key_id,
          enabled = 1,
          supports_tools = COALESCE(@tools, supports_tools),
          supports_vision = COALESCE(@vision, supports_vision)
      `).run({
        modelId, displayName, keyId: bindKeyId, customEndpointId, tools: toolsParam, vision: visionParam,
        intelligenceRank: seed.intelligenceRank, speedRank: seed.speedRank, sizeLabel: seed.sizeLabel,
      });

      const modelRow = db.prepare("SELECT id, supports_tools, supports_vision FROM models WHERE platform = 'custom' AND custom_endpoint_id = ? AND model_id = ?").get(customEndpointId, modelId) as { id: number; supports_tools: number; supports_vision: number };

      // Append to the fallback chain if not already present.
      const inChain = db.prepare('SELECT 1 FROM fallback_config WHERE model_db_id = ?').get(modelRow.id);
      if (!inChain) {
        const max = db.prepare('SELECT COALESCE(MAX(priority), 0) AS m FROM fallback_config').get() as { m: number };
        db.prepare('INSERT INTO fallback_config (model_db_id, priority, enabled) VALUES (?, ?, 1)').run(modelRow.id, max.m + 1);
      }
      ensureModelInProfiles(db, modelRow.id);

      registered.push({
        modelDbId: modelRow.id,
        model: modelId,
        displayName,
        supportsTools: modelRow.supports_tools === 1,
        supportsVision: modelRow.supports_vision === 1,
        created,
      });
    }

    return { keyId, registered, storedKeyForMask };
  });

  const { keyId, registered, storedKeyForMask } = upsert();
  // `model`/`displayName`/`modelDbId` echo the first model for older clients;
  // `models` carries the full set registered in this call.
  const first = registered[0]!;
  res.status(201).json({
    success: true,
    keyId,
    modelDbId: first.modelDbId,
    platform: 'custom',
    baseUrl,
    model: first.model,
    displayName: first.displayName,
    supportsTools: first.supportsTools,
    supportsVision: first.supportsVision,
    models: registered,
    // Bulk registration (#488) needs to tell the user what actually changed:
    // picking a whole discovered list re-submits ids that are already there.
    created: registered.filter(m => m.created).length,
    alreadyRegistered: registered.filter(m => !m.created).length,
    maskedKey: maskKey(storedKeyForMask),
  });
});

keysRouter.post('/import', (req: Request, res: Response, next: NextFunction) => {
  upload.single('file')(req, res, (err: any) => {
    if (handleUploadError(err, res, next)) return;

    try {
      if (!req.file) {
        res.status(400).json({ error: { message: 'No file uploaded' } });
        return;
      }

      const result = parseUpload(req.file);
      const imported: Array<{ keyName: string; platform: string }> = [];
      const skipped = [...result.skipped];
      const errors: Array<{ key: string; error: string }> = [];

      for (const parsedKey of result.keys) {
        const { keyName, keyValue } = splitRawKey(parsedKey.rawKey);
        if (!parsedKey.platform) {
          skipped.push(keyName);
          continue;
        }
        const platformParse = z.enum(PLATFORMS).safeParse(parsedKey.platform);
        if (!platformParse.success || platformParse.data === 'custom') {
          skipped.push(keyName);
          continue;
        }
        if (!keyValue.trim()) {
          errors.push({ key: keyName, error: 'keyValue must be at least 1 character' });
          continue;
        }

        try {
          insertImportedKey(platformParse.data, keyName, keyValue);
          imported.push({ keyName, platform: platformParse.data });
        } catch (insertErr) {
          errors.push({ key: keyName, error: (insertErr as Error).message });
        }
      }

      res.json({
        imported: imported.length,
        skipped,
        errors,
        total: result.keys.length + result.skipped.length,
      });
    } catch (handlerErr: any) {
      res.status(handlerErr.status ?? 500).json({ error: { message: handlerErr.message } });
    }
  });
});

keysRouter.post('/preview', (req: Request, res: Response, next: NextFunction) => {
  upload.array('files', 10)(req, res, (err: any) => {
    if (handleUploadError(err, res, next)) return;

    try {
      const files = req.files as Express.Multer.File[] | undefined;
      if (!files || files.length === 0) {
        res.status(400).json({ error: { message: 'No files uploaded' } });
        return;
      }

      const keys: Array<{ keyName: string; keyValue: string; detectedPlatform: string | null; prefix: string; isDuplicate: boolean }> = [];
      const skipped: string[] = [];

      // Build a set of existing decrypted key values for duplicate detection
      const db = getDb();
      const existingRows = db.prepare('SELECT encrypted_key, iv, auth_tag FROM api_keys').all() as any[];
      const existingKeys = new Set<string>();
      for (const row of existingRows) {
        try {
          existingKeys.add(decrypt(row.encrypted_key, row.iv, row.auth_tag));
        } catch { /* skip undecryptable rows */ }
      }

      let duplicateCount = 0;

      for (const file of files) {
        const result = parseUpload(file);
        for (const parsedKey of result.keys) {
          const { keyName, keyValue } = splitRawKey(parsedKey.rawKey);
          const isDuplicate = existingKeys.has(keyValue.trim());
          if (isDuplicate) duplicateCount++;
          keys.push({
            keyName,
            keyValue,
            detectedPlatform: parsedKey.platform,
            prefix: parsedKey.prefix,
            isDuplicate,
          });
        }
        skipped.push(...result.skipped);
      }

      res.json({ keys, total: keys.length, skipped, duplicates: duplicateCount });
    } catch (handlerErr: any) {
      res.status(handlerErr.status ?? 500).json({ error: { message: handlerErr.message } });
    }
  });
});

keysRouter.post('/import-selected', (req: Request, res: Response) => {
  const parsed = z.object({ keys: z.array(importKeySchema).max(100) }).safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: { message: parsed.error.errors.map(e => e.message).join(', ') } });
    return;
  }

  let imported = 0;
  let duplicateSkipped = 0;
  const errors: Array<{ key: string; error: string }> = [];

  // Build a set of existing decrypted key values for duplicate detection
  const db = getDb();
  const existingRows = db.prepare('SELECT encrypted_key, iv, auth_tag FROM api_keys').all() as any[];
  const existingKeys = new Set<string>();
  for (const row of existingRows) {
    try {
      existingKeys.add(decrypt(row.encrypted_key, row.iv, row.auth_tag));
    } catch { /* skip undecryptable rows */ }
  }

  for (const key of parsed.data.keys) {
    const keyName = key.keyName?.trim() || key.platform;
    if (key.platform === 'custom') {
      errors.push({ key: keyName, error: 'Custom providers must be added with a base URL' });
      continue;
    }

    if (existingKeys.has(key.keyValue.trim())) {
      duplicateSkipped++;
      errors.push({ key: keyName, error: 'Duplicate key — already exists' });
      continue;
    }

    try {
      insertImportedKey(key.platform, keyName, key.keyValue);
      imported++;
      existingKeys.add(key.keyValue.trim());
    } catch (err) {
      errors.push({ key: keyName, error: (err as Error).message });
    }
  }

  res.json({
    imported,
    skipped: [],
    errors,
    total: parsed.data.keys.length,
  });
});

// Delete a key
keysRouter.delete('/:id', (req: Request, res: Response) => {
  const id = parseInt(req.params.id as string, 10);
  if (isNaN(id)) {
    res.status(400).json({ error: { message: 'Invalid key ID' } });
    return;
  }

  const db = getDb();
  const row = db.prepare('SELECT platform, base_url, custom_endpoint_id FROM api_keys WHERE id = ?').get(id) as { platform: string; base_url: string | null; custom_endpoint_id: number | null } | undefined;
  if (!row) {
    res.status(404).json({ error: { message: 'Key not found' } });
    return;
  }
  // Another credential for the SAME endpoint keeps it alive — the models move
  // over to it instead of being cascaded away with this key (#619).
  const sibling = row.platform === 'custom' ? siblingEndpointKeyId(db, id, row.base_url) : null;

  const remove = db.transaction(() => {
    if (sibling != null) {
      if (row.platform === 'custom' && row.custom_endpoint_id != null) {
        db.prepare("UPDATE models SET key_id = ? WHERE platform = 'custom' AND custom_endpoint_id = ?").run(sibling, row.custom_endpoint_id);
      }
      for (const table of ['models', 'embedding_models', 'media_models']) {
        if (table === 'models' && row.platform === 'custom' && row.custom_endpoint_id != null) continue;
        db.prepare(`UPDATE ${table} SET key_id = ? WHERE platform = 'custom' AND key_id = ?`).run(sibling, id);
      }
      db.prepare('DELETE FROM api_keys WHERE id = ?').run(id);
      return;
    }

    db.prepare('DELETE FROM api_keys WHERE id = ?').run(id);
    // Custom models exist only because POST /custom registered them alongside
    // their endpoint key (#117) — they can't route without it. Cascade away
    // the models bound to THIS endpoint (#212); other custom providers keep
    // theirs. Legacy rows (key_id NULL) are swept once no custom keys remain,
    // so they never linger in the fallback chain forever (#189).
    if (row.platform === 'custom') {
      const defaultEmbedding = db.prepare("SELECT value FROM settings WHERE key = 'embeddings_default_family'").get() as { value: string } | undefined;
      if (row.custom_endpoint_id != null) {
        db.prepare("DELETE FROM fallback_config WHERE model_db_id IN (SELECT id FROM models WHERE platform = 'custom' AND custom_endpoint_id = ?)").run(row.custom_endpoint_id);
        db.prepare("DELETE FROM models WHERE platform = 'custom' AND custom_endpoint_id = ?").run(row.custom_endpoint_id);
        db.prepare('DELETE FROM custom_endpoints WHERE id = ?').run(row.custom_endpoint_id);
      } else {
        db.prepare("DELETE FROM fallback_config WHERE model_db_id IN (SELECT id FROM models WHERE platform = 'custom' AND key_id = ?)").run(id);
        db.prepare("DELETE FROM models WHERE platform = 'custom' AND key_id = ?").run(id);
      }
      db.prepare("DELETE FROM embedding_models WHERE platform = 'custom' AND key_id = ?").run(id);
      db.prepare("DELETE FROM media_models WHERE platform = 'custom' AND key_id = ?").run(id);
      const remaining = db.prepare("SELECT COUNT(*) AS n FROM api_keys WHERE platform = 'custom'").get() as { n: number };
      if (remaining.n === 0) {
        db.prepare("DELETE FROM fallback_config WHERE model_db_id IN (SELECT id FROM models WHERE platform = 'custom')").run();
        db.prepare("DELETE FROM models WHERE platform = 'custom'").run();
        db.prepare("DELETE FROM embedding_models WHERE platform = 'custom'").run();
        db.prepare("DELETE FROM media_models WHERE platform = 'custom'").run();
      }
      if (defaultEmbedding) {
        const stillExists = db.prepare('SELECT 1 FROM embedding_models WHERE family = ? LIMIT 1').get(defaultEmbedding.value);
        if (!stillExists) {
          const replacement = db.prepare('SELECT family FROM embedding_models ORDER BY family, priority LIMIT 1').get() as { family: string } | undefined;
          if (replacement) {
            db.prepare("UPDATE settings SET value = ? WHERE key = 'embeddings_default_family'").run(replacement.family);
          }
        }
      }
    }
  });
  remove();

  res.json({ success: true });
});

// Toggle all keys for a platform
keysRouter.patch('/platform/:platform', (req: Request, res: Response) => {
  const platform = req.params.platform as string;
  if (!(PLATFORMS as readonly string[]).includes(platform)) {
    res.status(400).json({ error: { message: `Invalid platform '${platform}'` } });
    return;
  }

  const { enabled } = req.body;
  if (typeof enabled !== 'boolean') {
    res.status(400).json({ error: { message: 'enabled must be a boolean' } });
    return;
  }

  const db = getDb();
  const result = db.prepare('UPDATE api_keys SET enabled = ? WHERE platform = ?').run(enabled ? 1 : 0, platform);

  res.json({ success: true, enabled, updatedKeys: result.changes });
});

// Update key (toggle enable/disable or edit label)
keysRouter.patch('/:id', (req: Request, res: Response) => {
  const id = parseInt(req.params.id as string, 10);
  if (isNaN(id)) {
    res.status(400).json({ error: { message: 'Invalid key ID' } });
    return;
  }

  const parsed = updateKeySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: { message: parsed.error.errors.map(e => e.message).join(', ') } });
    return;
  }

  const { enabled, label } = parsed.data;
  const updates: string[] = [];
  const values: (string | number)[] = [];

  if (enabled !== undefined) {
    updates.push('enabled = ?');
    values.push(enabled ? 1 : 0);
  }
  if (label !== undefined) {
    updates.push('label = ?');
    values.push(label);
  }

  values.push(id);

  const db = getDb();
  const result = db.prepare(`UPDATE api_keys SET ${updates.join(', ')} WHERE id = ?`).run(...values);

  if (result.changes === 0) {
    res.status(404).json({ error: { message: 'Key not found' } });
    return;
  }

  const response: Record<string, unknown> = { success: true };
  if (enabled !== undefined) response.enabled = enabled;
  if (label !== undefined) response.label = label;
  res.json(response);
});
