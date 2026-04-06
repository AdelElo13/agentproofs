import Database from 'better-sqlite3';
import { join } from 'node:path';
import type { ProofEntry, QueryParams } from './types.ts';

/**
 * SQLite sidecar index — derived cache, NOT trust anchor.
 * Rebuildable from JSONL segments. Used for fast queries only.
 */

export class ProofIndex {
  private db: Database.Database;

  constructor(dataDir: string) {
    this.db = new Database(join(dataDir, 'index.sqlite'));
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = NORMAL');
    this.initSchema();
  }

  private initSchema(): void {
    this.db.prepare(`
      CREATE TABLE IF NOT EXISTS proofs (
        id TEXT PRIMARY KEY,
        sequence INTEGER UNIQUE NOT NULL,
        event_type TEXT NOT NULL,
        tool TEXT,
        agent_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        trace_id TEXT,
        namespace TEXT,
        timestamp TEXT NOT NULL,
        success INTEGER NOT NULL,
        duration_ms INTEGER,
        segment_id TEXT,
        hash TEXT NOT NULL,
        prev_hash TEXT NOT NULL
      )
    `).run();

    this.db.prepare('CREATE INDEX IF NOT EXISTS idx_event_type ON proofs(event_type)').run();
    this.db.prepare('CREATE INDEX IF NOT EXISTS idx_tool ON proofs(tool)').run();
    this.db.prepare('CREATE INDEX IF NOT EXISTS idx_agent ON proofs(agent_id)').run();
    this.db.prepare('CREATE INDEX IF NOT EXISTS idx_session ON proofs(session_id)').run();
    this.db.prepare('CREATE INDEX IF NOT EXISTS idx_trace ON proofs(trace_id)').run();
    this.db.prepare('CREATE INDEX IF NOT EXISTS idx_namespace ON proofs(namespace)').run();
    this.db.prepare('CREATE INDEX IF NOT EXISTS idx_timestamp ON proofs(timestamp)').run();
    this.db.prepare('CREATE INDEX IF NOT EXISTS idx_success ON proofs(success)').run();

    this.db.prepare(`
      CREATE TABLE IF NOT EXISTS tags (
        proof_id TEXT NOT NULL,
        tag TEXT NOT NULL,
        PRIMARY KEY (proof_id, tag)
      )
    `).run();
    this.db.prepare('CREATE INDEX IF NOT EXISTS idx_tag ON tags(tag)').run();
  }

  indexProof(entry: ProofEntry, segmentId?: string): void {
    this.db.prepare(`
      INSERT OR REPLACE INTO proofs
      (id, sequence, event_type, tool, agent_id, session_id, trace_id,
       namespace, timestamp, success, duration_ms, segment_id, hash, prev_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      entry.id, entry.sequence, entry.event_type,
      entry.action.tool ?? null, entry.agent_id, entry.session_id,
      entry.trace_id ?? null, entry.context.namespace ?? null,
      entry.timestamp, entry.action.success ? 1 : 0,
      entry.action.duration_ms ?? null, segmentId ?? null,
      entry.hash, entry.prev_hash,
    );

    if (entry.context.tags && entry.context.tags.length > 0) {
      const tagStmt = this.db.prepare('INSERT OR IGNORE INTO tags (proof_id, tag) VALUES (?, ?)');
      for (const tag of entry.context.tags) {
        tagStmt.run(entry.id, tag);
      }
    }
  }

  bulkIndex(entries: readonly ProofEntry[], segmentId?: string): void {
    const tx = this.db.transaction(() => {
      for (const entry of entries) {
        this.indexProof(entry, segmentId);
      }
    });
    tx();
  }

  query(params: QueryParams): { ids: string[]; total: number } {
    const conditions: string[] = ['1=1'];
    const bindings: unknown[] = [];

    if (params.proof_id !== undefined) { conditions.push('p.id = ?'); bindings.push(params.proof_id); }
    if (params.agent_id !== undefined) { conditions.push('p.agent_id = ?'); bindings.push(params.agent_id); }
    if (params.session_id !== undefined) { conditions.push('p.session_id = ?'); bindings.push(params.session_id); }
    if (params.trace_id !== undefined) { conditions.push('p.trace_id = ?'); bindings.push(params.trace_id); }
    if (params.event_type !== undefined) { conditions.push('p.event_type = ?'); bindings.push(params.event_type); }
    if (params.tool !== undefined) { conditions.push('p.tool = ?'); bindings.push(params.tool); }
    if (params.namespace !== undefined) { conditions.push('p.namespace = ?'); bindings.push(params.namespace); }
    if (params.success !== undefined) { conditions.push('p.success = ?'); bindings.push(params.success ? 1 : 0); }
    if (params.from_date !== undefined) { conditions.push('p.timestamp >= ?'); bindings.push(params.from_date); }
    if (params.to_date !== undefined) { conditions.push('p.timestamp <= ?'); bindings.push(params.to_date); }

    if (params.tags !== undefined && params.tags.length > 0) {
      for (const tag of params.tags) {
        conditions.push('EXISTS (SELECT 1 FROM tags t WHERE t.proof_id = p.id AND t.tag = ?)');
        bindings.push(tag);
      }
    }

    const where = conditions.join(' AND ');
    const countRow = this.db.prepare(`SELECT COUNT(*) as cnt FROM proofs p WHERE ${where}`).get(...bindings) as { cnt: number };
    const total = countRow.cnt;

    const sort = params.sort === 'asc' ? 'ASC' : 'DESC';
    const limit = params.limit ?? 50;
    const offset = params.offset ?? 0;

    const rows = this.db.prepare(
      `SELECT p.id FROM proofs p WHERE ${where} ORDER BY p.sequence ${sort} LIMIT ? OFFSET ?`,
    ).all(...bindings, limit, offset) as Array<{ id: string }>;

    return { ids: rows.map((r) => r.id), total };
  }

  getLatestSequence(): number {
    const row = this.db.prepare('SELECT MAX(sequence) as seq FROM proofs').get() as { seq: number | null };
    return row.seq ?? 0;
  }

  getStats(): { total: number; byEventType: Record<string, number>; byTool: Record<string, number>; byAgent: Record<string, number> } {
    const total = (this.db.prepare('SELECT COUNT(*) as cnt FROM proofs').get() as { cnt: number }).cnt;

    const byEventType: Record<string, number> = {};
    for (const row of this.db.prepare('SELECT event_type, COUNT(*) as cnt FROM proofs GROUP BY event_type').all() as Array<{ event_type: string; cnt: number }>) {
      byEventType[row.event_type] = row.cnt;
    }

    const byTool: Record<string, number> = {};
    for (const row of this.db.prepare('SELECT tool, COUNT(*) as cnt FROM proofs WHERE tool IS NOT NULL GROUP BY tool').all() as Array<{ tool: string; cnt: number }>) {
      byTool[row.tool] = row.cnt;
    }

    const byAgent: Record<string, number> = {};
    for (const row of this.db.prepare('SELECT agent_id, COUNT(*) as cnt FROM proofs GROUP BY agent_id').all() as Array<{ agent_id: string; cnt: number }>) {
      byAgent[row.agent_id] = row.cnt;
    }

    return { total, byEventType, byTool, byAgent };
  }

  clear(): void {
    this.db.prepare('DELETE FROM tags').run();
    this.db.prepare('DELETE FROM proofs').run();
  }

  close(): void {
    this.db.close();
  }
}
