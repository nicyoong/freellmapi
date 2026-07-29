// Migration: stable custom-endpoint identity for chat models (#651)
// Created: 2026-07-29
//
// DOWN: reversible unless two endpoints now contain the same custom model id

import type { Db } from '../types.js';

interface CustomKeyRow {
  id: number;
  base_url: string | null;
}

function hasColumn(db: Db, table: string, column: string): boolean {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[];
  return columns.some((candidate) => candidate.name === column);
}

function normalizeBaseUrl(raw: string): string {
  return raw.trim().replace(/\/+$/, '');
}

function createModelsTable(db: Db, name: string, includeEndpoint: boolean): void {
  db.exec(`
    CREATE TABLE ${name} (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      platform TEXT NOT NULL,
      model_id TEXT NOT NULL,
      display_name TEXT NOT NULL,
      intelligence_rank INTEGER NOT NULL,
      speed_rank INTEGER NOT NULL,
      size_label TEXT NOT NULL DEFAULT '',
      rpm_limit INTEGER,
      rpd_limit INTEGER,
      tpm_limit INTEGER,
      tpd_limit INTEGER,
      monthly_token_budget TEXT NOT NULL DEFAULT '',
      context_window INTEGER,
      enabled INTEGER NOT NULL DEFAULT 1,
      supports_vision INTEGER NOT NULL DEFAULT 0,
      key_id INTEGER,
      supports_tools INTEGER NOT NULL DEFAULT 1,
      source TEXT NOT NULL DEFAULT 'catalog',
      paid_input_per_m REAL,
      paid_output_per_m REAL${includeEndpoint ? ',\n      custom_endpoint_id INTEGER REFERENCES custom_endpoints(id)' : ''}
    )
  `);
}

function stageModelReferences(db: Db): void {
  db.exec(`
    CREATE TABLE fallback_config_stage AS SELECT * FROM fallback_config;
    CREATE TABLE profile_models_stage AS SELECT * FROM profile_models;
    DROP TABLE fallback_config;
    DROP TABLE profile_models;
  `);
}

function restoreModelReferences(db: Db): void {
  db.exec(`
    CREATE TABLE fallback_config (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      model_db_id INTEGER NOT NULL REFERENCES models(id),
      priority INTEGER NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      UNIQUE(model_db_id)
    );
    INSERT INTO fallback_config (id, model_db_id, priority, enabled)
      SELECT id, model_db_id, priority, enabled FROM fallback_config_stage;
    DROP TABLE fallback_config_stage;

    CREATE TABLE profile_models (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      model_db_id INTEGER NOT NULL REFERENCES models(id) ON DELETE CASCADE,
      priority INTEGER NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      UNIQUE(profile_id, model_db_id)
    );
    INSERT INTO profile_models (id, profile_id, model_db_id, priority, enabled)
      SELECT id, profile_id, model_db_id, priority, enabled FROM profile_models_stage;
    DROP TABLE profile_models_stage;
  `);
}

function createIdentityIndexes(db: Db): void {
  db.exec(`
    CREATE UNIQUE INDEX idx_models_builtin_identity
      ON models(platform, model_id)
      WHERE platform != 'custom';
    CREATE UNIQUE INDEX idx_models_custom_endpoint_identity
      ON models(custom_endpoint_id, model_id)
      WHERE platform = 'custom' AND custom_endpoint_id IS NOT NULL;
    CREATE INDEX idx_models_custom_endpoint
      ON models(custom_endpoint_id)
      WHERE platform = 'custom';
  `);
}

export function up(db: Db): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS custom_endpoints (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      base_url TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  if (!hasColumn(db, 'api_keys', 'custom_endpoint_id')) {
    db.prepare('ALTER TABLE api_keys ADD COLUMN custom_endpoint_id INTEGER').run();
  }

  const customKeys = db.prepare(`
    SELECT id, base_url FROM api_keys
     WHERE platform = 'custom' AND base_url IS NOT NULL
  `).all() as CustomKeyRow[];
  const insertEndpoint = db.prepare('INSERT OR IGNORE INTO custom_endpoints (base_url) VALUES (?)');
  const findEndpoint = db.prepare('SELECT id FROM custom_endpoints WHERE base_url = ?');
  const bindKey = db.prepare('UPDATE api_keys SET custom_endpoint_id = ? WHERE id = ?');
  for (const key of customKeys) {
    const baseUrl = normalizeBaseUrl(key.base_url!);
    insertEndpoint.run(baseUrl);
    const endpoint = findEndpoint.get(baseUrl) as { id: number };
    bindKey.run(endpoint.id, key.id);
  }

  // SQLite cannot drop the old UNIQUE(platform, model_id) constraint in place.
  // Stage the two tables with foreign keys to models, rebuild while preserving
  // model ids, then restore those references against the replacement table.
  stageModelReferences(db);
  createModelsTable(db, 'models_next', true);
  db.exec(`
    INSERT INTO models_next (
      id, platform, model_id, display_name, intelligence_rank, speed_rank,
      size_label, rpm_limit, rpd_limit, tpm_limit, tpd_limit,
      monthly_token_budget, context_window, enabled, supports_vision, key_id,
      supports_tools, source, paid_input_per_m, paid_output_per_m, custom_endpoint_id
    )
    SELECT
      m.id, m.platform, m.model_id, m.display_name, m.intelligence_rank, m.speed_rank,
      m.size_label, m.rpm_limit, m.rpd_limit, m.tpm_limit, m.tpd_limit,
      m.monthly_token_budget, m.context_window, m.enabled,
      m.supports_vision, m.key_id, m.supports_tools, m.source,
      m.paid_input_per_m, m.paid_output_per_m,
      CASE WHEN m.platform = 'custom' THEN k.custom_endpoint_id ELSE NULL END
    FROM models m
    LEFT JOIN api_keys k ON k.id = m.key_id
  `);
  db.exec('DROP TABLE models; ALTER TABLE models_next RENAME TO models;');
  createIdentityIndexes(db);
  restoreModelReferences(db);

  if (!hasColumn(db, 'requests', 'model_db_id')) {
    db.prepare('ALTER TABLE requests ADD COLUMN model_db_id INTEGER').run();
    db.prepare('CREATE INDEX idx_requests_model_db_id ON requests(model_db_id)').run();
  }

  // Historical custom requests can be mapped exactly only while their key row
  // still exists. Leave orphaned history NULL rather than assigning it to the
  // wrong endpoint after a prior collision or key deletion.
  db.exec(`
    UPDATE requests
       SET model_db_id = (
         SELECT m.id FROM models m
          WHERE m.platform = requests.platform
            AND m.model_id = requests.model_id
            AND (
              m.platform != 'custom'
              OR m.custom_endpoint_id = (
                SELECT k.custom_endpoint_id FROM api_keys k WHERE k.id = requests.key_id
              )
            )
          LIMIT 1
       )
     WHERE model_db_id IS NULL;
  `);
}

export function down(db: Db): void {
  const duplicate = db.prepare(`
    SELECT model_id FROM models
     WHERE platform = 'custom'
     GROUP BY model_id
    HAVING COUNT(*) > 1
     LIMIT 1
  `).get() as { model_id: string } | undefined;
  if (duplicate) {
    throw new Error(`irreversible migration: custom model '${duplicate.model_id}' exists on multiple endpoints`);
  }

  stageModelReferences(db);
  createModelsTable(db, 'models_previous', false);
  db.exec(`
    INSERT INTO models_previous (
      id, platform, model_id, display_name, intelligence_rank, speed_rank,
      size_label, rpm_limit, rpd_limit, tpm_limit, tpd_limit,
      monthly_token_budget, context_window, enabled, supports_vision, key_id,
      supports_tools, source, paid_input_per_m, paid_output_per_m
    )
    SELECT
      id, platform, model_id, display_name, intelligence_rank, speed_rank,
      size_label, rpm_limit, rpd_limit, tpm_limit, tpd_limit,
      monthly_token_budget, context_window, enabled, supports_vision, key_id,
      supports_tools, source, paid_input_per_m, paid_output_per_m
    FROM models;
    DROP TABLE models;
    ALTER TABLE models_previous RENAME TO models;
    CREATE UNIQUE INDEX idx_models_legacy_identity ON models(platform, model_id);
  `);
  restoreModelReferences(db);

  db.prepare('DROP INDEX IF EXISTS idx_requests_model_db_id').run();
  if (hasColumn(db, 'requests', 'model_db_id')) {
    db.prepare('ALTER TABLE requests DROP COLUMN model_db_id').run();
  }
  if (hasColumn(db, 'api_keys', 'custom_endpoint_id')) {
    db.prepare('ALTER TABLE api_keys DROP COLUMN custom_endpoint_id').run();
  }
  db.prepare('DROP TABLE custom_endpoints').run();
}
