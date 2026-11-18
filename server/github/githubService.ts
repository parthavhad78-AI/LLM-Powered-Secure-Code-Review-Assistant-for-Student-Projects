import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type {
  GitHubRefreshResult,
  GitHubRepoValidation,
  Project,
} from '../../shared/types.ts';
import { getDb } from '../database/db.ts';
import {
  FileSecurityError,
  getProjectSourceDir,
  getProjectStorageRoot,
  MAX_ARCHIVE_BYTES,
  safeExtractZipToProject,
  type StoredFileMeta,
} from '../scanners/security/fileSecurity.ts';
import {
  type FetchLike,
  getUserGitHubAccessToken,
  GitHubError,
  isGitHubOAuthConfigured,
} from './githubOAuth.ts';

const ALLOWED_GITHUB_HOSTS = new Set([
  'api.github.com',
  'codeload.github.com',
  'github.com',
  'objects.githubusercontent.com',
]);

const MAX_REDIRECT_HOPS = 5;
const GITHUB_OWNER_REGEX = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;
const GITHUB_REPO_REGEX = /^[A-Za-z0-9._-]+$/;

export interface ParsedGitHubUrl {
  owner: string;
  repo: string;
  canonicalUrl: string;
  branchFromUrl: string | null;
}

export function parseGitHubRepoUrl(rawInput: string): ParsedGitHubUrl {
  const trimmed = String(rawInput || '').trim();
  if (!trimmed) {
    throw new GitHubError('GitHub repository URL is required.', 400);
  }
  if (/[\s\0\\;&|`$<>!]/.test(trimmed)) {
    throw new GitHubError('GitHub URL contains invalid whitespace or disallowed characters.', 400);
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new GitHubError('Invalid GitHub repository URL format. Use https://github.com/owner/repo.', 400);
  }

  if (parsed.protocol !== 'https:') {
    throw new GitHubError('Only HTTPS GitHub URLs (https://github.com/owner/repo) are permitted.', 400);
  }

  if (parsed.username || parsed.password) {
    throw new GitHubError('Embedded credentials in GitHub URLs are not allowed.', 400);
  }

  if (parsed.port) {
    throw new GitHubError('Custom ports in GitHub URLs are not allowed.', 400);
  }

  const host = parsed.hostname.toLowerCase();
  if (host !== 'github.com' && host !== 'www.github.com') {
    throw new GitHubError('Only github.com repository URLs are permitted.', 400);
  }

  if (parsed.search || parsed.hash) {
    throw new GitHubError('Query parameters and URL fragments are not permitted in repository URLs.', 400);
  }

  const rawSegments = parsed.pathname.split('/').filter((s) => s.length > 0);
  if (rawSegments.length < 2) {
    throw new GitHubError('GitHub URL must include both owner and repository name (https://github.com/owner/repo).', 400);
  }

  for (const seg of rawSegments) {
    if (seg === '.' || seg === '..' || decodeURIComponent(seg).includes('..')) {
      throw new GitHubError('Path traversal segments are not allowed in GitHub URLs.', 400);
    }
  }

  const owner = rawSegments[0];
  let repo = rawSegments[1];
  if (repo.endsWith('.git')) {
    repo = repo.slice(0, -4);
  }

  if (!GITHUB_OWNER_REGEX.test(owner)) {
    throw new GitHubError('Invalid GitHub repository owner name.', 400);
  }

  if (!repo || repo === '.' || repo === '..' || !GITHUB_REPO_REGEX.test(repo)) {
    throw new GitHubError('Invalid GitHub repository name.', 400);
  }

  let branchFromUrl: string | null = null;
  if (rawSegments.length > 2) {
    if (rawSegments[2] === 'tree' && rawSegments.length >= 4) {
      branchFromUrl = rawSegments.slice(3).join('/');
      if (!branchFromUrl || /[\s\0]/.test(branchFromUrl)) {
        throw new GitHubError('Invalid branch name in GitHub URL.', 400);
      }
    } else {
      throw new GitHubError(
        'Unsupported GitHub URL path. Provide https://github.com/owner/repo or https://github.com/owner/repo/tree/branch.',
        400
      );
    }
  }

  return {
    owner,
    repo,
    canonicalUrl: `https://github.com/${owner}/${repo}`,
    branchFromUrl,
  };
}

function assertAllowedGitHubRequestUrl(rawUrl: string): URL {
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    throw new GitHubError('Invalid upstream GitHub request URL.', 400);
  }
  if (u.protocol !== 'https:') {
    throw new GitHubError(`Disallowed non-HTTPS redirect or request scheme: ${u.protocol}`, 400);
  }
  if (u.username || u.password || u.port) {
    throw new GitHubError('Disallowed URL authority parameters.', 400);
  }
  const host = u.hostname.toLowerCase();
  if (!ALLOWED_GITHUB_HOSTS.has(host)) {
    throw new GitHubError(`Blocked outbound request to disallowed host: ${host}`, 403);
  }
  return u;
}

export async function safeGitHubFetch(
  initialUrl: string,
  options: {
    headers?: Record<string, string>;
    timeoutMs?: number;
    signal?: AbortSignal;
  } = {},
  fetchImpl: FetchLike = fetch
): Promise<Response> {
  let currentUrl = assertAllowedGitHubRequestUrl(initialUrl);
  const timeoutMs = options.timeoutMs ?? 15000;

  for (let hop = 0; hop <= MAX_REDIRECT_HOPS; hop++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error('GitHub request timed out.')), timeoutMs);
    const onCallerAbort = () => controller.abort(options.signal?.reason || new Error('Cancelled'));

    if (options.signal) {
      if (options.signal.aborted) {
        clearTimeout(timer);
        throw new GitHubError('GitHub operation was cancelled.', 499);
      }
      options.signal.addEventListener('abort', onCallerAbort, { once: true });
    }

    const reqHeaders: Record<string, string> = {
      'User-Agent': 'SecureLens-App',
      ...(options.headers || {}),
    };
    // Never forward GitHub OAuth Authorization tokens to non-api.github.com CDN redirect hosts
    if (currentUrl.hostname.toLowerCase() !== 'api.github.com') {
      delete reqHeaders.Authorization;
      delete reqHeaders.authorization;
    }

    let res: Response;
    try {
      res = await fetchImpl(currentUrl.toString(), {
        method: 'GET',
        headers: reqHeaders,
        redirect: 'manual',
        signal: controller.signal,
      });
    } catch (err) {
      clearTimeout(timer);
      if (options.signal) options.signal.removeEventListener('abort', onCallerAbort);
      if (options.signal?.aborted) {
        throw new GitHubError('GitHub operation was cancelled.', 499);
      }
      const msg = err instanceof Error ? err.message : 'Network error';
      if (/abort|timed out/i.test(msg)) {
        throw new GitHubError('GitHub request timed out. Please try again.', 504);
      }
      throw new GitHubError(`Failed to reach GitHub: ${msg}`, 502);
    }

    clearTimeout(timer);
    if (options.signal) options.signal.removeEventListener('abort', onCallerAbort);

    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get('location');
      if (!location) {
        throw new GitHubError('GitHub returned an incomplete redirect response.', 502);
      }
      const resolvedNext = new URL(location, currentUrl).toString();
      currentUrl = assertAllowedGitHubRequestUrl(resolvedNext);
      continue;
    }

    return res;
  }

  throw new GitHubError('Too many redirects returned by GitHub.', 502);
}

function buildGitHubHeaders(token: string | null): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  return headers;
}

function mapGitHubApiError(
  status: number,
  bodyText: string,
  hasToken: boolean,
  oauthConfigured: boolean
): GitHubError {
  if (status === 404) {
    if (!hasToken) {
      return new GitHubError(
        oauthConfigured
          ? 'Repository not found or is private. Connect your GitHub account via OAuth to import private repositories.'
          : 'Repository not found or is private. Public repositories can be imported directly; private repositories require GitHub OAuth configuration on the server.',
        404
      );
    }
    return new GitHubError('GitHub repository or branch was not found, or your account lacks read access.', 404);
  }
  if (status === 401) {
    return new GitHubError(
      hasToken
        ? 'Your GitHub OAuth session expired or was revoked. Reconnect GitHub and try again.'
        : 'Authentication required to access this GitHub repository.',
      401
    );
  }
  if (status === 403) {
    if (/rate limit/i.test(bodyText)) {
      return new GitHubError(
        hasToken
          ? 'GitHub API rate limit exceeded. Please wait a few minutes and try again.'
          : 'GitHub unauthenticated API rate limit reached. Connect GitHub OAuth or retry shortly.',
        429
      );
    }
    return new GitHubError(
      'Access forbidden by GitHub. Ensure the repository is accessible or grant `repo` scope.',
      403
    );
  }
  if (status === 429) {
    return new GitHubError('GitHub API rate limit reached. Please try again shortly.', 429);
  }
  return new GitHubError(`GitHub API returned unexpected status ${status}.`, 502);
}

export async function validateGitHubRepository(params: {
  userId: string;
  repoUrl: string;
  branch?: string | null;
  fetchImpl?: FetchLike;
  signal?: AbortSignal;
}): Promise<GitHubRepoValidation> {
  const parsed = parseGitHubRepoUrl(params.repoUrl);
  const fetcher = params.fetchImpl ?? fetch;
  const token = getUserGitHubAccessToken(params.userId);
  const oauthConfigured = isGitHubOAuthConfigured();
  const headers = buildGitHubHeaders(token);

  const repoRes = await safeGitHubFetch(
    `https://api.github.com/repos/${encodeURIComponent(parsed.owner)}/${encodeURIComponent(parsed.repo)}`,
    { headers, timeoutMs: 15000, signal: params.signal },
    fetcher
  );

  if (!repoRes.ok) {
    const bodyText = await repoRes.text().catch(() => '');
    throw mapGitHubApiError(repoRes.status, bodyText, Boolean(token), oauthConfigured);
  }

  const repoJson = (await repoRes.json()) as {
    full_name?: string;
    name?: string;
    description?: string | null;
    private?: boolean;
    default_branch?: string;
    html_url?: string;
    size?: number;
    owner?: { login?: string };
  };

  const defaultBranch = repoJson.default_branch || 'main';
  const selectedBranch = (params.branch?.trim() || parsed.branchFromUrl || defaultBranch).trim();

  // Fetch branch list for UI selection
  const branchesRes = await safeGitHubFetch(
    `https://api.github.com/repos/${encodeURIComponent(parsed.owner)}/${encodeURIComponent(parsed.repo)}/branches?per_page=100`,
    { headers, timeoutMs: 15000, signal: params.signal },
    fetcher
  );

  let availableBranches: string[] = [defaultBranch];
  if (branchesRes.ok) {
    const branchList = (await branchesRes.json()) as Array<{ name?: string; commit?: { sha?: string } }>;
    const names = branchList.map((b) => String(b.name || '')).filter(Boolean);
    if (names.length > 0) {
      availableBranches = names;
    }
  }

  // Resolve exact commit SHA for the selected branch
  const commitRes = await safeGitHubFetch(
    `https://api.github.com/repos/${encodeURIComponent(parsed.owner)}/${encodeURIComponent(parsed.repo)}/commits/${encodeURIComponent(selectedBranch)}`,
    { headers, timeoutMs: 15000, signal: params.signal },
    fetcher
  );

  if (!commitRes.ok) {
    if (commitRes.status === 404 || commitRes.status === 422) {
      throw new GitHubError(`Branch "${selectedBranch}" was not found in ${parsed.owner}/${parsed.repo}.`, 404);
    }
    const bodyText = await commitRes.text().catch(() => '');
    throw mapGitHubApiError(commitRes.status, bodyText, Boolean(token), oauthConfigured);
  }

  const commitJson = (await commitRes.json()) as { sha?: string };
  const commitSha = String(commitJson.sha || '').trim();
  if (!commitSha) {
    throw new GitHubError(`Could not resolve commit SHA for branch "${selectedBranch}".`, 502);
  }

  if (!availableBranches.includes(selectedBranch)) {
    availableBranches = [selectedBranch, ...availableBranches];
  }

  return {
    url: parsed.canonicalUrl,
    owner: repoJson.owner?.login || parsed.owner,
    repo: repoJson.name || parsed.repo,
    description: repoJson.description || '',
    isPrivate: Boolean(repoJson.private),
    defaultBranch,
    selectedBranch,
    commitSha,
    branches: availableBranches,
  };
}

async function downloadZipballWithinLimit(params: {
  url: string;
  headers: Record<string, string>;
  maxBytes: number;
  signal?: AbortSignal;
  fetchImpl: FetchLike;
}): Promise<Buffer> {
  const res = await safeGitHubFetch(
    params.url,
    { headers: params.headers, timeoutMs: 45000, signal: params.signal },
    params.fetchImpl
  );

  if (!res.ok) {
    throw new GitHubError(`Failed to download repository archive (HTTP ${res.status}).`, res.status === 404 ? 404 : 502);
  }

  const contentLength = Number(res.headers.get('content-length') || 0);
  if (contentLength > params.maxBytes) {
    throw new FileSecurityError(
      `Repository archive exceeds maximum allowed size of ${params.maxBytes / (1024 * 1024)} MB.`,
      413
    );
  }

  if (!res.body || typeof res.body.getReader !== 'function') {
    const arr = Buffer.from(await res.arrayBuffer());
    if (arr.length > params.maxBytes) {
      throw new FileSecurityError(
        `Repository archive exceeds maximum allowed size of ${params.maxBytes / (1024 * 1024)} MB.`,
        413
      );
    }
    return arr;
  }

  const reader = res.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > params.maxBytes) {
        await reader.cancel().catch(() => {});
        throw new FileSecurityError(
          `Repository archive exceeds maximum allowed size of ${params.maxBytes / (1024 * 1024)} MB.`,
          413
        );
      }
      chunks.push(Buffer.from(value));
    }
  }

  return Buffer.concat(chunks);
}

export function mapDbProjectRow(row: Record<string, unknown>): Project {
  return {
    id: String(row.id),
    userId: String(row.user_id),
    name: String(row.name),
    description: String(row.description || ''),
    primaryLanguage: row.primary_language ? String(row.primary_language) : null,
    languages: JSON.parse(String(row.languages_json || '[]')),
    fileCount: Number(row.file_count || 0),
    totalBytes: Number(row.total_bytes || 0),
    importMethod: (row.import_method as Project['importMethod']) || 'upload',
    githubRepoUrl: row.github_repo_url ? String(row.github_repo_url) : null,
    githubOwner: row.github_owner ? String(row.github_owner) : null,
    githubRepo: row.github_repo ? String(row.github_repo) : null,
    githubBranch: row.github_branch ? String(row.github_branch) : null,
    githubCommitSha: row.github_commit_sha ? String(row.github_commit_sha) : null,
    githubIsPrivate: Boolean(row.github_is_private),
    lastImportedAt: row.last_imported_at ? String(row.last_imported_at) : null,
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
    lastScanAt: row.last_scan_at ? String(row.last_scan_at) : null,
    openFindingsCount: row.open_findings_count !== undefined ? Number(row.open_findings_count) : undefined,
  };
}

function summarizeStoredLanguages(storedMeta: StoredFileMeta[]): {
  primaryLanguage: string | null;
  languages: string[];
  totalBytes: number;
} {
  const langBytes = new Map<string, number>();
  let totalBytes = 0;
  for (const f of storedMeta) {
    totalBytes += f.sizeBytes;
    if (
      ![
        'JSON / Config',
        'Text / Manifest',
        'Lockfile',
        'Dependency Manifest',
        'Environment Config',
        'Other',
      ].includes(f.language)
    ) {
      langBytes.set(f.language, (langBytes.get(f.language) || 0) + f.sizeBytes);
    }
  }
  const sortedLangs = Array.from(langBytes.entries())
    .sort((a, b) => b[1] - a[1])
    .map((e) => e[0]);
  const allLangs = Array.from(new Set(storedMeta.map((f) => f.language)));
  return {
    primaryLanguage: sortedLangs[0] || allLangs[0] || null,
    languages: allLangs,
    totalBytes,
  };
}

export async function importGitHubRepository(params: {
  userId: string;
  projectId?: string;
  projectName?: string;
  description?: string;
  repoUrl: string;
  branch?: string | null;
  fetchImpl?: FetchLike;
  signal?: AbortSignal;
}): Promise<{
  project: Project;
  validation: GitHubRepoValidation;
  importedFilesCount: number;
}> {
  const db = getDb();
  const isNewProject = !params.projectId;
  const projectId = params.projectId || crypto.randomUUID();

  if (!isNewProject) {
    const owned = db
      .prepare('SELECT id FROM projects WHERE id = ? AND user_id = ?')
      .get(projectId, params.userId);
    if (!owned) {
      throw new GitHubError('Project not found or access denied.', 404);
    }
  }

  const validation = await validateGitHubRepository({
    userId: params.userId,
    repoUrl: params.repoUrl,
    branch: params.branch,
    fetchImpl: params.fetchImpl,
    signal: params.signal,
  });

  const token = getUserGitHubAccessToken(params.userId);
  const fetcher = params.fetchImpl ?? fetch;
  const zipballUrl = `https://api.github.com/repos/${encodeURIComponent(validation.owner)}/${encodeURIComponent(validation.repo)}/zipball/${encodeURIComponent(validation.commitSha)}`;

  const maxArchiveBytes = Number(process.env.GITHUB_MAX_ARCHIVE_BYTES || MAX_ARCHIVE_BYTES);
  const zipBuffer = await downloadZipballWithinLimit({
    url: zipballUrl,
    headers: buildGitHubHeaders(token),
    maxBytes: maxArchiveBytes,
    signal: params.signal,
    fetchImpl: fetcher,
  });

  const stagingDir = fs.mkdtempSync(path.join(os.tmpdir(), 'securelens-gh-'));
  const sourceDir = getProjectSourceDir(params.userId, projectId);
  let extractedMeta: StoredFileMeta[] = [];

  try {
    extractedMeta = safeExtractZipToProject(zipBuffer, stagingDir);

    const { primaryLanguage, languages, totalBytes } = summarizeStoredLanguages(extractedMeta);
    const now = new Date().toISOString();
    const resolvedName = (params.projectName?.trim() || `${validation.owner}/${validation.repo}`).slice(0, 80);
    const resolvedDesc = (
      params.description !== undefined ? params.description : validation.description
    )
      .trim()
      .slice(0, 500);

    // Swap staged files cleanly into project source directory
    fs.mkdirSync(path.dirname(sourceDir), { recursive: true });
    fs.rmSync(sourceDir, { recursive: true, force: true });
    fs.mkdirSync(sourceDir, { recursive: true });
    fs.cpSync(stagingDir, sourceDir, { recursive: true });

    const tx = db.transaction(() => {
      if (isNewProject) {
        db.prepare(
          `INSERT INTO projects (
            id, user_id, name, description, primary_language, languages_json, source_path,
            file_count, total_bytes, import_method, github_repo_url, github_owner, github_repo,
            github_branch, github_commit_sha, github_is_private, last_imported_at, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'github', ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).run(
          projectId,
          params.userId,
          resolvedName,
          resolvedDesc,
          primaryLanguage,
          JSON.stringify(languages),
          sourceDir,
          extractedMeta.length,
          totalBytes,
          validation.url,
          validation.owner,
          validation.repo,
          validation.selectedBranch,
          validation.commitSha,
          validation.isPrivate ? 1 : 0,
          now,
          now,
          now
        );
      } else {
        db.prepare(
          `UPDATE projects SET
             primary_language = ?,
             languages_json = ?,
             file_count = ?,
             total_bytes = ?,
             import_method = 'github',
             github_repo_url = ?,
             github_owner = ?,
             github_repo = ?,
             github_branch = ?,
             github_commit_sha = ?,
             github_is_private = ?,
             last_imported_at = ?,
             updated_at = ?
           WHERE id = ? AND user_id = ?`
        ).run(
          primaryLanguage,
          JSON.stringify(languages),
          extractedMeta.length,
          totalBytes,
          validation.url,
          validation.owner,
          validation.repo,
          validation.selectedBranch,
          validation.commitSha,
          validation.isPrivate ? 1 : 0,
          now,
          now,
          projectId,
          params.userId
        );
        db.prepare('DELETE FROM project_files WHERE project_id = ?').run(projectId);
      }

      const insertFile = db.prepare(
        `INSERT INTO project_files (id, project_id, relative_path, language, size_bytes, sha256, is_supported, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      );
      for (const meta of extractedMeta) {
        insertFile.run(
          crypto.randomUUID(),
          projectId,
          meta.relativePath,
          meta.language,
          meta.sizeBytes,
          meta.sha256,
          meta.isSupported ? 1 : 0,
          now
        );
      }
    });

    tx();

    const projectRow = db.prepare('SELECT * FROM projects WHERE id = ?').get(projectId) as Record<string, unknown>;
    return {
      project: mapDbProjectRow(projectRow),
      validation,
      importedFilesCount: extractedMeta.length,
    };
  } catch (err) {
    // Ensure a failed new import never leaves behind empty project storage or dangling rows
    if (isNewProject) {
      try {
        fs.rmSync(getProjectStorageRoot(params.userId, projectId), { recursive: true, force: true });
      } catch {
        // best effort
      }
    }
    throw err;
  } finally {
    fs.rmSync(stagingDir, { recursive: true, force: true });
  }
}

export async function refreshGitHubProject(params: {
  userId: string;
  projectId: string;
  fetchImpl?: FetchLike;
  signal?: AbortSignal;
}): Promise<GitHubRefreshResult> {
  const db = getDb();
  const row = db
    .prepare('SELECT * FROM projects WHERE id = ? AND user_id = ?')
    .get(params.projectId, params.userId) as Record<string, unknown> | undefined;

  if (!row) {
    throw new GitHubError('Project not found or access denied.', 404);
  }

  if (row.import_method !== 'github' || !row.github_repo_url) {
    throw new GitHubError('This project was not imported from GitHub.', 400);
  }

  const repoUrl = String(row.github_repo_url);
  const branch = row.github_branch ? String(row.github_branch) : undefined;
  const previousCommitSha = row.github_commit_sha ? String(row.github_commit_sha) : null;

  const validation = await validateGitHubRepository({
    userId: params.userId,
    repoUrl,
    branch,
    fetchImpl: params.fetchImpl,
    signal: params.signal,
  });

  if (previousCommitSha && previousCommitSha === validation.commitSha) {
    return {
      changed: false,
      previousCommitSha,
      latestCommitSha: validation.commitSha,
      branch: validation.selectedBranch,
      importedCount: Number(row.file_count || 0),
      project: mapDbProjectRow(row),
    };
  }

  const imported = await importGitHubRepository({
    userId: params.userId,
    projectId: params.projectId,
    repoUrl,
    branch: validation.selectedBranch,
    fetchImpl: params.fetchImpl,
    signal: params.signal,
  });

  return {
    changed: true,
    previousCommitSha,
    latestCommitSha: imported.validation.commitSha,
    branch: imported.validation.selectedBranch,
    importedCount: imported.importedFilesCount,
    project: imported.project,
  };
}
