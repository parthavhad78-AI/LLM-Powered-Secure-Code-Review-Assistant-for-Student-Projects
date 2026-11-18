import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import type Database from 'better-sqlite3';
import { getDb } from '../database/db.ts';
import type { StudentUser } from '../../shared/types.ts';

const BCRYPT_ROUNDS = 12;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

export interface AuthSession {
  sessionIdHash: string;
  userId: string;
  csrfToken: string;
  expiresAt: string;
  user: StudentUser;
}

export function hashSessionToken(rawToken: string): string {
  return crypto.createHash('sha256').update(rawToken).digest('hex');
}

export function validateEmail(email: string): boolean {
  const trimmed = email.trim();
  if (trimmed.length < 5 || trimmed.length > 254) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed);
}

export function validatePasswordStrength(password: string): string | null {
  if (typeof password !== 'string' || password.length < 8) {
    return 'Password must be at least 8 characters long.';
  }
  if (password.length > 128) {
    return 'Password must not exceed 128 characters.';
  }
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password)) {
    return 'Password must include both uppercase and lowercase letters.';
  }
  if (!/[0-9]/.test(password) && !/[^A-Za-z0-9]/.test(password)) {
    return 'Password must include at least one number or special character.';
  }
  return null;
}

export async function registerStudent(
  params: { fullName: string; email: string; password: string; confirmPassword: string },
  db: Database.Database = getDb()
): Promise<StudentUser> {
  const fullName = params.fullName.trim();
  const email = params.email.trim().toLowerCase();

  if (fullName.length < 2 || fullName.length > 100) {
    throw new AuthError('Full name must be between 2 and 100 characters.', 400);
  }
  if (!validateEmail(email)) {
    throw new AuthError('Please enter a valid email address.', 400);
  }
  if (params.password !== params.confirmPassword) {
    throw new AuthError('Passwords do not match.', 400);
  }
  const strengthError = validatePasswordStrength(params.password);
  if (strengthError) {
    throw new AuthError(strengthError, 400);
  }

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) {
    throw new AuthError('An account with this email already exists.', 409);
  }

  const id = crypto.randomUUID();
  const passwordHash = await bcrypt.hash(params.password, BCRYPT_ROUNDS);
  const now = new Date().toISOString();
  const defaultModel = process.env.GEMINI_MODEL || 'gemini-4-hydrogen';

  db.prepare(
    `INSERT INTO users (id, full_name, email, password_hash, preferred_model, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(id, fullName, email, passwordHash, defaultModel, now, now);

  return {
    id,
    fullName,
    email,
    preferredModel: defaultModel,
    createdAt: now,
  };
}

export async function authenticateStudent(
  params: { email: string; password: string },
  db: Database.Database = getDb()
): Promise<StudentUser> {
  const email = params.email.trim().toLowerCase();
  if (!validateEmail(email) || typeof params.password !== 'string' || !params.password) {
    throw new AuthError('Invalid email or password.', 401);
  }

  const row = db
    .prepare(
      `SELECT id, full_name, email, password_hash, preferred_model, created_at
       FROM users WHERE email = ?`
    )
    .get(email) as
    | {
        id: string;
        full_name: string;
        email: string;
        password_hash: string;
        preferred_model: string;
        created_at: string;
      }
    | undefined;

  if (!row) {
    // Perform constant-time dummy compare to mitigate timing enumeration
    await bcrypt.compare(params.password, '$2b$12$C6UzMDM.H6dfI/f/IKcEeO6qF3I4Z1tP8H7n1q4q4Z5pL6M2H1e5S');
    throw new AuthError('Invalid email or password.', 401);
  }

  const valid = await bcrypt.compare(params.password, row.password_hash);
  if (!valid) {
    throw new AuthError('Invalid email or password.', 401);
  }

  return {
    id: row.id,
    fullName: row.full_name,
    email: row.email,
    preferredModel: row.preferred_model,
    createdAt: row.created_at,
  };
}

export function createSession(
  userId: string,
  meta: { userAgent?: string; ipAddress?: string } = {},
  db: Database.Database = getDb()
): { rawToken: string; csrfToken: string; expiresAt: string } {
  const rawToken = crypto.randomBytes(32).toString('hex');
  const sessionIdHash = hashSessionToken(rawToken);
  const csrfToken = crypto.randomBytes(24).toString('hex');
  const now = Date.now();
  const createdAt = new Date(now).toISOString();
  const expiresAt = new Date(now + SESSION_TTL_MS).toISOString();

  // Opportunistic cleanup of expired sessions for this user
  db.prepare('DELETE FROM sessions WHERE user_id = ? AND expires_at <= ?').run(userId, createdAt);

  db.prepare(
    `INSERT INTO sessions (id, user_id, csrf_token, expires_at, created_at, user_agent, ip_address)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(
    sessionIdHash,
    userId,
    csrfToken,
    expiresAt,
    createdAt,
    meta.userAgent?.slice(0, 250) || null,
    meta.ipAddress?.slice(0, 64) || null
  );

  return { rawToken, csrfToken, expiresAt };
}

export function getSessionByRawToken(
  rawToken: string,
  db: Database.Database = getDb()
): AuthSession | null {
  if (!rawToken || typeof rawToken !== 'string') return null;
  const sessionIdHash = hashSessionToken(rawToken);
  const row = db
    .prepare(
      `SELECT s.id AS session_id, s.user_id, s.csrf_token, s.expires_at,
              u.full_name, u.email, u.preferred_model, u.created_at
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.id = ?`
    )
    .get(sessionIdHash) as
    | {
        session_id: string;
        user_id: string;
        csrf_token: string;
        expires_at: string;
        full_name: string;
        email: string;
        preferred_model: string;
        created_at: string;
      }
    | undefined;

  if (!row) return null;

  if (new Date(row.expires_at).getTime() <= Date.now()) {
    db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionIdHash);
    return null;
  }

  return {
    sessionIdHash: row.session_id,
    userId: row.user_id,
    csrfToken: row.csrf_token,
    expiresAt: row.expires_at,
    user: {
      id: row.user_id,
      fullName: row.full_name,
      email: row.email,
      preferredModel: row.preferred_model,
      createdAt: row.created_at,
    },
  };
}

export function deleteSessionByRawToken(rawToken: string, db: Database.Database = getDb()): void {
  if (!rawToken) return;
  const sessionIdHash = hashSessionToken(rawToken);
  db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionIdHash);
}

export async function changeStudentPassword(
  userId: string,
  currentPassword: string,
  newPassword: string,
  confirmPassword: string,
  db: Database.Database = getDb()
): Promise<void> {
  if (newPassword !== confirmPassword) {
    throw new AuthError('New passwords do not match.', 400);
  }
  const strengthError = validatePasswordStrength(newPassword);
  if (strengthError) {
    throw new AuthError(strengthError, 400);
  }
  const row = db
    .prepare('SELECT password_hash FROM users WHERE id = ?')
    .get(userId) as { password_hash: string } | undefined;
  if (!row) {
    throw new AuthError('Account not found.', 404);
  }
  const matches = await bcrypt.compare(currentPassword, row.password_hash);
  if (!matches) {
    throw new AuthError('Current password is incorrect.', 401);
  }

  const newHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  db.prepare('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?').run(
    newHash,
    new Date().toISOString(),
    userId
  );
}

export class AuthError extends Error {
  statusCode: number;
  constructor(message: string, statusCode = 400) {
    super(message);
    this.name = 'AuthError';
    this.statusCode = statusCode;
  }
}
