// Migration: attach request history to the concrete model row that served it.
// Created: 2026-07-30
//
// Custom relays may share an upstream model id, so (platform, model_id) is no
// longer enough to identify the row whose price, reliability, and speed apply.

import type { Db } from '../types.js';

export function up(db: Db): void {
  db.exec(`
    ALTER TABLE requests ADD COLUMN model_db_id INTEGER REFERENCES models(id);
    CREATE INDEX idx_requests_model_db_id ON requests(model_db_id);
  `);

  // Historical catalog requests remain unambiguous. A custom request can be
  // attributed only while its key survives: the key's normalized base URL is
  // the endpoint_scope of the concrete model row. Leave orphaned custom rows
  // NULL rather than assigning their traffic to the wrong relay.
  db.exec(`
    UPDATE requests
       SET model_db_id = (
         SELECT m.id
           FROM models m
          WHERE m.platform = requests.platform
            AND m.model_id = requests.model_id
            AND (
              m.platform != 'custom'
              OR m.endpoint_scope = (
                SELECT rtrim(trim(k.base_url), '/')
                  FROM api_keys k
                 WHERE k.id = requests.key_id
                   AND k.platform = 'custom'
              )
            )
          LIMIT 1
       )
     WHERE model_db_id IS NULL;
  `);
}

export function down(db: Db): void {
  db.exec(`
    DROP INDEX IF EXISTS idx_requests_model_db_id;
    ALTER TABLE requests DROP COLUMN model_db_id;
  `);
}
