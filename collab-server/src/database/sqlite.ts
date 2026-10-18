import Database from 'better-sqlite3';
import * as path from 'path';
import * as fs from 'fs';
import type { DBAdapter } from './adapter';

export class SQLiteAdapter implements DBAdapter {
  private db: Database.Database;
  private operationQueue: Promise<void> = Promise.resolve();

  constructor(dataDir: string) {
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }

    const dbPath = path.join(dataDir, 'collab.sqlite3');
    this.db = new Database(dbPath);

    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
  }

  async run(sql: string, params: unknown[] = []): Promise<{ changes: number }> {
    return this.enqueue(() => this.runDirect(sql, params));
  }

  async get<T = any>(sql: string, params: unknown[] = []): Promise<T | undefined> {
    return this.enqueue(() => this.getDirect<T>(sql, params));
  }

  async all<T = any>(sql: string, params: unknown[] = []): Promise<T[]> {
    return this.enqueue(() => this.allDirect<T>(sql, params));
  }

  async exec(sql: string): Promise<void> {
    await this.enqueue(() => { this.db.exec(sql); });
  }

  async transaction<T>(operation: (db: DBAdapter) => Promise<T>): Promise<T> {
    return this.enqueue(async () => {
      this.db.exec('BEGIN IMMEDIATE');
      const transactionAdapter: DBAdapter = {
        run: async (sql, params = []) => this.runDirect(sql, params),
        get: async <TRow = any>(sql: string, params: unknown[] = []) => (
          this.getDirect<TRow>(sql, params)
        ),
        all: async <TRow = any>(sql: string, params: unknown[] = []) => (
          this.allDirect<TRow>(sql, params)
        ),
        exec: async (sql) => { this.db.exec(sql); },
        transaction: async () => {
          throw new Error('Nested SQLite transactions are not supported');
        },
        close: async () => {
          throw new Error('Cannot close a transaction adapter');
        },
      };
      try {
        const result = await operation(transactionAdapter);
        this.db.exec('COMMIT');
        return result;
      } catch (error) {
        this.db.exec('ROLLBACK');
        throw error;
      }
    });
  }

  async close(): Promise<void> {
    await this.enqueue(() => { this.db.close(); });
  }

  private runDirect(sql: string, params: unknown[]): { changes: number } {
    const result = this.db.prepare(sql).run(...params);
    return { changes: result.changes };
  }

  private getDirect<T>(sql: string, params: unknown[]): T | undefined {
    return this.db.prepare(sql).get(...params) as T | undefined;
  }

  private allDirect<T>(sql: string, params: unknown[]): T[] {
    return this.db.prepare(sql).all(...params) as T[];
  }

  private async enqueue<T>(operation: () => T | Promise<T>): Promise<T> {
    const previous = this.operationQueue;
    let release!: () => void;
    this.operationQueue = new Promise<void>((resolve) => { release = resolve; });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }
}
