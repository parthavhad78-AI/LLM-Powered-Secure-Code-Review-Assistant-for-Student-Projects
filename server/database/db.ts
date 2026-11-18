import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';
import { runMigrations } from './schema.ts';

let dbInstance: Database.Database | null = null;

export function getDatabasePath(): string {
  return process.env.DATABASE_PATH || path.resolve(process.cwd(), 'data', 'securelens.db');
}

export function initDatabase(customPath?: string): Database.Database {
  const dbPath = customPath ?? getDatabasePath();

  const fileExistedBefore = dbPath !== ':memory:' && fs.existsSync(dbPath);
  if (dbPath !== ':memory:') {
    const dir = path.dirname(path.resolve(dbPath));
    fs.mkdirSync(dir, { recursive: true });
  }

  const db = new Database(dbPath);
  db.pragma('foreign_keys = ON');
  if (dbPath !== ':memory:') {
    db.pragma('journal_mode = WAL');
  }
  db.pragma('busy_timeout = 5000');

  if (fileExistedBefore && dbPath !== ':memory:') {
    try {
      const hasMigrationsTable = db
        .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'")
        .get();
      const hasV3 = hasMigrationsTable
        ? db.prepare('SELECT 1 FROM schema_migrations WHERE version = 3').get()
        : undefined;
      const backupPath = `${dbPath}.pre-v3.bak`;
      if (hasMigrationsTable && !hasV3 && !fs.existsSync(backupPath)) {
        db.pragma('wal_checkpoint(TRUNCATE)');
        fs.copyFileSync(dbPath, backupPath);
        const stat = fs.statSync(backupPath);
        if (stat.size <= 0) {
          throw new Error('Created pre-v3 database backup was empty.');
        }
      }
    } catch (err) {
      db.close();
      throw err;
    }
  }

  runMigrations(db);
  dbInstance = db;
  return db;
}

export function getDb(): Database.Database {
  if (!dbInstance) {
    return initDatabase();
  }
  return dbInstance;
}

export function closeDb(): void {
  if (dbInstance) {
    dbInstance.close();
    dbInstance = null;
  }
}
