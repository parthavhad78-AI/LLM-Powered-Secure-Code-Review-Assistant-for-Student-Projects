import crypto from 'node:crypto';
import type { Request } from 'express';
import type { GitHubStatus } from '../../shared/types.ts';
import { getDb } from '../database/db.ts';

export class GitHubError extends Error {
  statusCode: number;
  constructor(message: string, statusCode = 400) {
    super(message);
    this.name = 'GitHubError';
    this.statusCode = statusCode;
  }
}

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export const GITHUB_TOKEN_ENCRYPTION_ENV_VAR = 'GITHUB_TOKEN_ENCRYPTION_KEY' as const;

export interface GitHubEnvValidationResult {
  oauthConfigured: boolean;
  encryptionKeyConfigured: boolean;
  encryptionEnvVar: typeof GITHUB_TOKEN_ENCRYPTION_ENV_VAR;
  legacyMisnamedEnvDetected: boolean;
  warnings: string[];
}

function getTokenEncryptionKey(): Buffer {
  const configuredKey = process.env.GITHUB_TOKEN_ENCRYPTION_KEY?.trim();
  const sessionSecret = process.env.SESSION_SECRET?.trim();
  const raw = configuredKey || sessionSecret || 'securelens-local-dev-github-token-key';
  return crypto.createHash('sha256').update(raw).digest();
}

export function encryptGitHubToken(plainToken: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getTokenEncryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(plainToken, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('base64')}:${tag.toString('base64')}:${encrypted.toString('base64')}`;
}

export function decryptGitHubToken(payload: string): string {
  const parts = payload.split(':');
  if (parts.length !== 3) {
    throw new GitHubError('Stored GitHub credential format is invalid.', 500);
  }
  const [ivB64, tagB64, cipherB64] = parts;
  const iv = Buffer.from(ivB64, 'base64');
  const tag = Buffer.from(tagB64, 'base64');
  const encrypted = Buffer.from(cipherB64, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', getTokenEncryptionKey(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

export function isGitHubOAuthConfigured(): boolean {
  return Boolean(process.env.GITHUB_CLIENT_ID?.trim() && process.env.GITHUB_CLIENT_SECRET?.trim());
}

export function validateGitHubEnvironment(): GitHubEnvValidationResult {
  const clientId = process.env.GITHUB_CLIENT_ID?.trim() || '';
  const clientSecret = process.env.GITHUB_CLIENT_SECRET?.trim() || '';
  const encryptionKey = process.env.GITHUB_TOKEN_ENCRYPTION_KEY?.trim() || '';
  const legacyMisnamed = Boolean(process.env.GITHUB_TOKEN_ENCRYPTION?.trim()) && !encryptionKey;

  const warnings: string[] = [];
  if ((clientId && !clientSecret) || (!clientId && clientSecret)) {
    warnings.push(
      'Both GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET must be set to enable private GitHub OAuth.'
    );
  }
  if (legacyMisnamed) {
    warnings.push(
      'Detected GITHUB_TOKEN_ENCRYPTION, which is not read by the backend. Configure GITHUB_TOKEN_ENCRYPTION_KEY instead.'
    );
  }
  if (clientId && clientSecret && !encryptionKey && process.env.NODE_ENV === 'production') {
    warnings.push(
      'GITHUB_TOKEN_ENCRYPTION_KEY is not set; GitHub OAuth token encryption is falling back to SESSION_SECRET or the default key.'
    );
  }

  return {
    oauthConfigured: Boolean(clientId && clientSecret),
    encryptionKeyConfigured: Boolean(encryptionKey),
    encryptionEnvVar: GITHUB_TOKEN_ENCRYPTION_ENV_VAR,
    legacyMisnamedEnvDetected: legacyMisnamed,
    warnings,
  };
}

export function getAppBaseUrl(req?: Request): string {
  if (process.env.APP_URL?.trim()) {
    return process.env.APP_URL.trim().replace(/\/+$/, '');
  }
  if (req) {
    const proto = (req.headers['x-forwarded-proto'] as string)?.split(',')[0]?.trim() || req.protocol;
    const host = (req.headers['x-forwarded-host'] as string)?.split(',')[0]?.trim() || req.get('host');
    if (host) {
      return `${proto}://${host}`;
    }
  }
  return `http://localhost:${process.env.PORT || 3000}`;
}

export function getGitHubCallbackUrl(req?: Request): string {
  return `${getAppBaseUrl(req)}/api/github/oauth/callback`;
}

export function createGitHubOAuthUrl(params: { userId: string; req?: Request }): {
  authUrl: string;
  callbackUrl: string;
  state: string;
} {
  if (!isGitHubOAuthConfigured()) {
    throw new GitHubError(
      'GitHub OAuth is not configured on this server (GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET missing). Public GitHub repositories can still be imported without authentication.',
      503
    );
  }

  const db = getDb();
  const now = new Date();
  const nowIso = now.toISOString();
  const expiresIso = new Date(now.getTime() + 10 * 60 * 1000).toISOString();
  const state = crypto.randomBytes(32).toString('hex');

  db.prepare('DELETE FROM github_oauth_states WHERE expires_at <= ?').run(nowIso);
  db.prepare(
    'INSERT INTO github_oauth_states (state, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)'
  ).run(state, params.userId, expiresIso, nowIso);

  const callbackUrl = getGitHubCallbackUrl(params.req);
  const query = new URLSearchParams({
    client_id: process.env.GITHUB_CLIENT_ID!.trim(),
    redirect_uri: callbackUrl,
    scope: 'repo read:user',
    state,
    allow_signup: 'false',
  });

  return {
    authUrl: `https://github.com/login/oauth/authorize?${query.toString()}`,
    callbackUrl,
    state,
  };
}

export async function completeGitHubOAuthCallback(params: {
  code: string;
  state: string;
  callbackUrl: string;
  fetchImpl?: FetchLike;
}): Promise<{ userId: string; githubUsername: string }> {
  if (!isGitHubOAuthConfigured()) {
    throw new GitHubError('GitHub OAuth is not configured on the server.', 503);
  }

  const db = getDb();
  const nowIso = new Date().toISOString();
  const stateRow = db
    .prepare('SELECT state, user_id, expires_at FROM github_oauth_states WHERE state = ?')
    .get(params.state) as { state: string; user_id: string; expires_at: string } | undefined;

  if (!stateRow) {
    throw new GitHubError('Invalid or already used GitHub OAuth state parameter.', 400);
  }

  // Single-use state cleanup immediately
  db.prepare('DELETE FROM github_oauth_states WHERE state = ?').run(params.state);

  if (stateRow.expires_at <= nowIso) {
    throw new GitHubError('GitHub OAuth session expired. Please try connecting again.', 400);
  }

  const fetcher = params.fetchImpl ?? fetch;
  const tokenRes = await fetcher('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      'User-Agent': 'SecureLens-App',
    },
    body: JSON.stringify({
      client_id: process.env.GITHUB_CLIENT_ID!.trim(),
      client_secret: process.env.GITHUB_CLIENT_SECRET!.trim(),
      code: params.code,
      redirect_uri: params.callbackUrl,
    }),
  });

  if (!tokenRes.ok) {
    throw new GitHubError('Failed to exchange GitHub authorization code.', 502);
  }

  const tokenData = (await tokenRes.json()) as {
    access_token?: string;
    scope?: string;
    error?: string;
    error_description?: string;
  };

  if (tokenData.error || !tokenData.access_token) {
    throw new GitHubError(
      tokenData.error_description || tokenData.error || 'GitHub did not return an access token.',
      400
    );
  }

  const userRes = await fetcher('https://api.github.com/user', {
    headers: {
      Authorization: `Bearer ${tokenData.access_token}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'SecureLens-App',
    },
  });

  if (!userRes.ok) {
    throw new GitHubError('Failed to verify GitHub account profile.', 502);
  }

  const ghUser = (await userRes.json()) as { id?: number | string; login?: string };
  const githubUserId = String(ghUser.id || '');
  const githubUsername = String(ghUser.login || 'github-user');
  if (!githubUserId) {
    throw new GitHubError('GitHub user profile response was missing user ID.', 502);
  }

  const encrypted = encryptGitHubToken(tokenData.access_token);
  const scope = String(tokenData.scope || '');

  db.prepare(
    `INSERT INTO github_connections (id, user_id, github_user_id, github_username, access_token_encrypted, scope, connected_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(user_id) DO UPDATE SET
       github_user_id = excluded.github_user_id,
       github_username = excluded.github_username,
       access_token_encrypted = excluded.access_token_encrypted,
       scope = excluded.scope,
       updated_at = excluded.updated_at`
  ).run(crypto.randomUUID(), stateRow.user_id, githubUserId, githubUsername, encrypted, scope, nowIso, nowIso);

  return { userId: stateRow.user_id, githubUsername };
}

export function getGitHubConnectionStatus(userId: string, req?: Request): GitHubStatus {
  const db = getDb();
  const row = db
    .prepare(
      'SELECT github_username, scope, connected_at FROM github_connections WHERE user_id = ?'
    )
    .get(userId) as
    | { github_username: string; scope: string; connected_at: string }
    | undefined;

  return {
    publicImportEnabled: true,
    oauthConfigured: isGitHubOAuthConfigured(),
    connected: Boolean(row),
    username: row ? row.github_username : null,
    scopes: row ? row.scope : null,
    callbackUrl: getGitHubCallbackUrl(req),
  };
}

export function getUserGitHubAccessToken(userId: string): string | null {
  const db = getDb();
  const row = db
    .prepare('SELECT access_token_encrypted FROM github_connections WHERE user_id = ?')
    .get(userId) as { access_token_encrypted: string } | undefined;

  if (!row) return null;
  try {
    return decryptGitHubToken(row.access_token_encrypted);
  } catch {
    return null;
  }
}

export async function disconnectGitHubConnection(params: {
  userId: string;
  fetchImpl?: FetchLike;
}): Promise<void> {
  const db = getDb();
  const existing = db
    .prepare('SELECT access_token_encrypted FROM github_connections WHERE user_id = ?')
    .get(params.userId) as { access_token_encrypted: string } | undefined;

  if (existing && isGitHubOAuthConfigured()) {
    try {
      const token = decryptGitHubToken(existing.access_token_encrypted);
      const clientId = process.env.GITHUB_CLIENT_ID!.trim();
      const clientSecret = process.env.GITHUB_CLIENT_SECRET!.trim();
      const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
      const fetcher = params.fetchImpl ?? fetch;
      await fetcher(`https://api.github.com/applications/${encodeURIComponent(clientId)}/token`, {
        method: 'DELETE',
        headers: {
          Authorization: `Basic ${basicAuth}`,
          Accept: 'application/vnd.github+json',
          'Content-Type': 'application/json',
          'User-Agent': 'SecureLens-App',
        },
        body: JSON.stringify({ access_token: token }),
      });
    } catch {
      // Always proceed to remove local connection even if upstream revocation fails
    }
  }

  db.prepare('DELETE FROM github_connections WHERE user_id = ?').run(params.userId);
}
