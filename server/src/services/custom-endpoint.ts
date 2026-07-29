import { encrypt, decrypt } from '../lib/crypto.js';
import type { Db } from '../db/types.js';

// ── Custom OpenAI-compatible endpoints: keys per endpoint ────────────────────
// A custom endpoint is identified by its base_url and can hold SEVERAL
// credentials — relay services routinely hand out one key per plan/group, and
// pooling them is the whole point of adding more than one (#619). Registration
// therefore matches on (base_url, secret), never on base_url alone: a new
// secret for a known endpoint INSERTs, it does not overwrite the key already
// stored. Models bind to the stable custom_endpoints row; key_id is retained as
// the pool's preferred credential, while the router can rotate within that
// endpoint's credentials.

// Stored for endpoints that need no credential (llama.cpp / LM Studio / vLLM
// with auth off). It is a placeholder, not a secret, so a real key may replace
// it in place instead of piling up a second row.
const NO_KEY = 'no-key';

interface StoredKeyRow {
  id: number;
  encrypted_key: string;
  iv: string;
  auth_tag: string;
}

function endpointIdForBaseUrl(db: Db, baseUrl: string): number {
  db.prepare('INSERT OR IGNORE INTO custom_endpoints (base_url) VALUES (?)').run(baseUrl);
  return (db.prepare('SELECT id FROM custom_endpoints WHERE base_url = ?').get(baseUrl) as { id: number }).id;
}

export function customEndpointIdForKey(db: Db, keyId: number): number | null {
  const row = db.prepare('SELECT custom_endpoint_id FROM api_keys WHERE id = ? AND platform = \'custom\'').get(keyId) as
    { custom_endpoint_id: number | null } | undefined;
  return row?.custom_endpoint_id ?? null;
}

export interface ResolvedEndpointKey {
  keyId: number;
  /** Plaintext of the key now bound to this endpoint — for masking in responses. */
  storedKey: string;
  /** True when this call added a credential rather than updating one. */
  created: boolean;
}

function endpointKeyRows(db: Db, baseUrl: string): StoredKeyRow[] {
  return db.prepare(`
    SELECT id, encrypted_key, iv, auth_tag
      FROM api_keys
     WHERE platform = 'custom' AND base_url = ?
     ORDER BY id
  `).all(baseUrl) as StoredKeyRow[];
}

function plaintextOf(row: StoredKeyRow): string | null {
  try {
    return decrypt(row.encrypted_key, row.iv, row.auth_tag);
  } catch {
    return null;
  }
}

function touch(db: Db, id: number, label: string | undefined): void {
  db.prepare("UPDATE api_keys SET label = COALESCE(?, label), status = 'unknown', enabled = 1 WHERE id = ?")
    .run(label ?? null, id);
}

function insertKey(db: Db, baseUrl: string, secret: string, label: string | undefined): ResolvedEndpointKey {
  const { encrypted, iv, authTag } = encrypt(secret);
  const endpointId = endpointIdForBaseUrl(db, baseUrl);
  const r = db.prepare(`
    INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled, base_url, custom_endpoint_id)
    VALUES ('custom', ?, ?, ?, ?, 'unknown', 1, ?, ?)
  `).run(label ?? 'Custom', encrypted, iv, authTag, baseUrl, endpointId);
  return { keyId: Number(r.lastInsertRowid), storedKey: secret, created: true };
}

/**
 * Resolve the api_keys row a custom-endpoint registration should bind to,
 * creating or updating it as needed. Never destroys a stored credential:
 *  - no key submitted        → reuse the endpoint's first key (label refresh only)
 *  - a key already on record  → update that row (label / re-enable)
 *  - a new key, placeholder-only endpoint → replace the placeholder in place
 *  - a new key, endpoint already has one → INSERT a second credential (#619)
 *
 * `pinnedKeyId` lets a caller that already knows WHICH credential of the pool
 * it is acting for name it — the bulk registration of discovered models (#488)
 * comes back holding the key row the user fetched the list with. It only
 * applies when that row really serves this base_url and no new secret was
 * submitted; a new secret still goes through the rules above.
 */
export function resolveCustomEndpointKey(
  db: Db,
  baseUrl: string,
  providedKey: string | undefined,
  label: string | undefined,
  pinnedKeyId?: number,
): ResolvedEndpointKey {
  const rows = endpointKeyRows(db, baseUrl);
  const stored = rows.map(row => ({ row, secret: plaintextOf(row) }));

  if (!providedKey) {
    const pinned = pinnedKeyId === undefined
      ? undefined
      : stored.find(s => s.row.id === pinnedKeyId);
    const first = pinned ?? stored[0];
    if (!first) return insertKey(db, baseUrl, NO_KEY, label);
    touch(db, first.row.id, label);
    return { keyId: first.row.id, storedKey: first.secret ?? NO_KEY, created: false };
  }

  const same = stored.find(s => s.secret === providedKey);
  if (same) {
    touch(db, same.row.id, label);
    return { keyId: same.row.id, storedKey: providedKey, created: false };
  }

  // Only placeholders on record: the endpoint was registered without auth and
  // is being given a key now, so upgrade rather than leave a dead sentinel row.
  if (stored.length > 0 && stored.every(s => s.secret === NO_KEY)) {
    const target = stored[0]!.row;
    const { encrypted, iv, authTag } = encrypt(providedKey);
    db.prepare(`
      UPDATE api_keys
         SET label = COALESCE(?, label), encrypted_key = ?, iv = ?, auth_tag = ?,
             status = 'unknown', enabled = 1
       WHERE id = ?
    `).run(label ?? null, encrypted, iv, authTag, target.id);
    return { keyId: target.id, storedKey: providedKey, created: false };
  }

  return insertKey(db, baseUrl, providedKey, label);
}

/**
 * Every api_keys id that serves the SAME custom endpoint as `keyId` — i.e. the
 * credential pool a model bound to `keyId` may rotate across. Falls back to the
 * key itself when the row is gone or carries no base_url.
 */
export function customEndpointKeyIds(db: Db, keyId: number): Set<number> {
  const row = db.prepare('SELECT custom_endpoint_id FROM api_keys WHERE id = ?').get(keyId) as
    { custom_endpoint_id: number | null } | undefined;
  if (row?.custom_endpoint_id == null) return new Set([keyId]);
  const siblings = db.prepare("SELECT id FROM api_keys WHERE platform = 'custom' AND custom_endpoint_id = ?")
    .all(row.custom_endpoint_id) as { id: number }[];
  return new Set(siblings.map(s => s.id));
}

/**
 * The other key still serving this endpoint once `keyId` is gone, or null when
 * it was the last one. Used to re-home an endpoint's models instead of deleting
 * them with the key.
 */
export function siblingEndpointKeyId(db: Db, keyId: number, baseUrl: string | null): number | null {
  const endpoint = customEndpointIdForKey(db, keyId);
  if (endpoint != null) {
    const sibling = db.prepare(`
      SELECT id FROM api_keys
       WHERE platform = 'custom' AND custom_endpoint_id = ? AND id != ?
       ORDER BY id LIMIT 1
    `).get(endpoint, keyId) as { id: number } | undefined;
    return sibling?.id ?? null;
  }
  if (!baseUrl) return null;
  const row = db.prepare(`
    SELECT id FROM api_keys
     WHERE platform = 'custom' AND base_url = ? AND id != ?
     ORDER BY id LIMIT 1
  `).get(baseUrl, keyId) as { id: number } | undefined;
  return row?.id ?? null;
}
