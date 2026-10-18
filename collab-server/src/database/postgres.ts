import { Pool, type PoolClient } from 'pg';
import type { DBAdapter } from './adapter';

/** Convert `?` placeholders to PostgreSQL `$1, $2, ...` style. */
function toPgPlaceholders(sql: string): string {
  let index = 0;
  return sql.replace(/\?/g, () => `$${++index}`);
}

/**
 * Convert SQLite-flavoured DDL to PostgreSQL.
 *  - INTEGER PRIMARY KEY AUTOINCREMENT → SERIAL PRIMARY KEY
 */
function adaptDDL(sql: string): string {
  return sql.replace(
    /INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT/gi,
    'SERIAL PRIMARY KEY',
  );
}

export class PostgresAdapter implements DBAdapter {
  private pool: Pool;

  constructor(opts: {
    host: string;
    port: number;
    database: string;
    user: string;
    password: string;
  }) {
    this.pool = new Pool({
      host: opts.host,
      port: opts.port,
      database: opts.database,
      user: opts.user,
      password: opts.password,
      max: 20,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000,
    });

    this.pool.on('error', (err) => {
      console.error('Unexpected PostgreSQL pool error:', err);
    });
  }

  async run(sql: string, params: unknown[] = []): Promise<{ changes: number }> {
    const result = await this.pool.query(toPgPlaceholders(sql), params);
    return { changes: result.rowCount ?? 0 };
  }

  async get<T = any>(sql: string, params: unknown[] = []): Promise<T | undefined> {
    const result = await this.pool.query(toPgPlaceholders(sql), params);
    return result.rows[0] as T | undefined;
  }

  async all<T = any>(sql: string, params: unknown[] = []): Promise<T[]> {
    const result = await this.pool.query(toPgPlaceholders(sql), params);
    return result.rows as T[];
  }

  async exec(sql: string): Promise<void> {
    const adapted = adaptDDL(sql);
    await this.pool.query(adapted);
  }

  async transaction<T>(operation: (db: DBAdapter) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await operation(new PostgresTransactionAdapter(client));
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

class PostgresTransactionAdapter implements DBAdapter {
  constructor(private readonly client: PoolClient) {}

  async run(sql: string, params: unknown[] = []): Promise<{ changes: number }> {
    const result = await this.client.query(toPgPlaceholders(sql), params);
    return { changes: result.rowCount ?? 0 };
  }

  async get<T = any>(sql: string, params: unknown[] = []): Promise<T | undefined> {
    const result = await this.client.query(toPgPlaceholders(sql), params);
    return result.rows[0] as T | undefined;
  }

  async all<T = any>(sql: string, params: unknown[] = []): Promise<T[]> {
    const result = await this.client.query(toPgPlaceholders(sql), params);
    return result.rows as T[];
  }

  async exec(sql: string): Promise<void> {
    await this.client.query(adaptDDL(sql));
  }

  async transaction<T>(_operation: (db: DBAdapter) => Promise<T>): Promise<T> {
    throw new Error('Nested PostgreSQL transactions are not supported');
  }

  async close(): Promise<void> {
    throw new Error('Cannot close a transaction adapter');
  }
}
