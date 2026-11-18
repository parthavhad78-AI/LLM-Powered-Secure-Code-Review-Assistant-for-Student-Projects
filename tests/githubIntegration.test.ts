import AdmZip from 'adm-zip';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../server.ts';
import { closeDb, getDb } from '../server/database/db.ts';
import {
  completeGitHubOAuthCallback,
  createGitHubOAuthUrl,
  decryptGitHubToken,
  disconnectGitHubConnection,
  encryptGitHubToken,
  getGitHubConnectionStatus,
  getUserGitHubAccessToken,
  GITHUB_TOKEN_ENCRYPTION_ENV_VAR,
  validateGitHubEnvironment,
  type FetchLike,
} from '../server/github/githubOAuth.ts';
import {
  importGitHubRepository,
  parseGitHubRepoUrl,
  refreshGitHubProject,
  safeGitHubFetch,
  validateGitHubRepository,
} from '../server/github/githubService.ts';
import { detectFileLanguage } from '../server/scanners/security/fileSecurity.ts';

let tmpDir: string;
let server: http.Server;
let baseUrl: string;
const createdUserDirs: string[] = [];

beforeEach(async () => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sl-gh-test-'));
  process.env.DATABASE_PATH = path.join(tmpDir, 'github.db');
  process.env.GITHUB_CLIENT_ID = 'test-gh-client-id';
  process.env.GITHUB_CLIENT_SECRET = 'test-gh-client-secret';
  process.env.GITHUB_TOKEN_ENCRYPTION_KEY = 'test-encryption-secret-32-bytes-key!';

  const app = createApp();
  await new Promise<void>((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (addr && typeof addr === 'object') {
        baseUrl = `http://127.0.0.1:${addr.port}`;
      }
      resolve();
    });
  });
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  closeDb();
  delete process.env.DATABASE_PATH;
  delete process.env.GITHUB_CLIENT_ID;
  delete process.env.GITHUB_CLIENT_SECRET;
  delete process.env.GITHUB_TOKEN_ENCRYPTION_KEY;
  fs.rmSync(tmpDir, { recursive: true, force: true });
  for (const dir of createdUserDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

async function registerStudent(fullName: string, email: string) {
  const res = await fetch(`${baseUrl}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      fullName,
      email,
      password: 'Password123!',
      confirmPassword: 'Password123!',
    }),
  });
  expect(res.status).toBe(201);
  const cookie = res.headers.get('set-cookie')?.split(';')[0] || '';
  const body = (await res.json()) as { user: { id: string }; csrfToken: string };
  createdUserDirs.push(
    path.join(process.cwd(), 'data', 'projects', body.user.id.replace(/[^a-zA-Z0-9_-]/g, ''))
  );
  return { user: body.user, cookie, csrfToken: body.csrfToken };
}

function buildZipBuffer(entries: Array<{ name: string; content: string | Buffer; symlink?: boolean }>): Buffer {
  const zip = new AdmZip();
  entries.forEach((e, idx) => {
    zip.addFile(
      `placeholder-${idx}.txt`,
      typeof e.content === 'string' ? Buffer.from(e.content, 'utf8') : e.content
    );
    const added = zip.getEntries()[zip.getEntries().length - 1];
    if (added) {
      added.entryName = e.name;
      if (e.symlink) {
        // Set Unix symlink mode (0120777) in external attributes
        added.header.attr = (0o120777 << 16) >>> 0;
      }
    }
  });
  return zip.toBuffer();
}

function createMockGitHubFetcher(options: {
  commitSha?: string;
  isPrivate?: boolean;
  requiresAuth?: boolean;
  zipBuffer?: Buffer;
  redirectLocation?: string;
  sawAuthOnCdnRedirect?: { value: boolean };
}): FetchLike {
  const sha = options.commitSha || 'a1b2c3d4e5f60708091011121314151617181920';
  return async (url: string, init?: RequestInit): Promise<Response> => {
    const authHeader =
      init?.headers && !Array.isArray(init.headers)
        ? (init.headers as Record<string, string>).Authorization ||
          (init.headers as Record<string, string>).authorization
        : undefined;

    if (url.startsWith('https://api.github.com/repos/octo/demo/zipball/')) {
      if (options.redirectLocation) {
        return new Response(null, {
          status: 302,
          headers: { Location: options.redirectLocation },
        });
      }
      return new Response(new Uint8Array(options.zipBuffer || Buffer.alloc(0)), {
        status: 200,
        headers: { 'Content-Type': 'application/zip' },
      });
    }

    if (url.startsWith('https://codeload.github.com/')) {
      if (authHeader && options.sawAuthOnCdnRedirect) {
        options.sawAuthOnCdnRedirect.value = true;
      }
      return new Response(new Uint8Array(options.zipBuffer || Buffer.alloc(0)), {
        status: 200,
        headers: { 'Content-Type': 'application/zip' },
      });
    }

    if (options.requiresAuth && !authHeader) {
      return new Response(JSON.stringify({ message: 'Not Found' }), { status: 404 });
    }

    if (url === 'https://api.github.com/repos/octo/demo') {
      return new Response(
        JSON.stringify({
          full_name: 'octo/demo',
          name: 'demo',
          description: 'Mocked student repo',
          private: Boolean(options.isPrivate),
          default_branch: 'main',
          size: 42,
          owner: { login: 'octo' },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    }

    if (url.startsWith('https://api.github.com/repos/octo/demo/branches')) {
      return new Response(
        JSON.stringify([{ name: 'main' }, { name: 'feature/auth' }]),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    }

    if (url.startsWith('https://api.github.com/repos/octo/demo/commits/')) {
      return new Response(JSON.stringify({ sha }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (url === 'https://github.com/login/oauth/access_token') {
      return new Response(
        JSON.stringify({ access_token: 'gho_mocked_secret_token_12345', scope: 'repo,read:user' }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    }

    if (url === 'https://api.github.com/user') {
      return new Response(JSON.stringify({ id: 99123, login: 'octo-student' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (url.startsWith('https://api.github.com/applications/')) {
      return new Response(null, { status: 204 });
    }

    return new Response(JSON.stringify({ message: 'Unhandled mock URL' }), { status: 404 });
  };
}

describe('GitHub Integration, Security Hardening & Refresh Workflow', () => {
  it('validates GitHub URLs strictly and rejects SSRF, non-HTTPS, credentials, ports, and shell characters', () => {
    const validBasic = parseGitHubRepoUrl('https://github.com/octo/demo');
    expect(validBasic).toEqual({
      owner: 'octo',
      repo: 'demo',
      canonicalUrl: 'https://github.com/octo/demo',
      branchFromUrl: null,
    });

    const validBranch = parseGitHubRepoUrl('https://github.com/octo/demo.git');
    expect(validBranch.canonicalUrl).toBe('https://github.com/octo/demo');

    const validTree = parseGitHubRepoUrl('https://github.com/octo/demo/tree/feature/auth');
    expect(validTree.branchFromUrl).toBe('feature/auth');

    const badUrls = [
      'http://github.com/octo/demo',
      'file:///etc/passwd',
      'git://github.com/octo/demo.git',
      'javascript:alert(1)',
      'https://evil.com/octo/demo',
      'https://127.0.0.1/octo/demo',
      'https://169.254.169.254/latest/meta-data',
      'https://user:pass@github.com/octo/demo',
      'https://github.com:8443/octo/demo',
      'https://github.com/octo/../secret',
      'https://github.com/octo/demo?token=1',
      'https://github.com/octo/demo;rm -rf /',
      'https://github.com/octo',
    ];
    for (const u of badUrls) {
      expect(() => parseGitHubRepoUrl(u)).toThrow();
    }
  });

  it('blocks SSRF redirects to internal/disallowed hosts and strips Authorization headers across allowed CDN redirects', async () => {
    await expect(
      safeGitHubFetch(
        'https://api.github.com/repos/octo/demo/zipball/main',
        { headers: { Authorization: 'Bearer secret' } },
        createMockGitHubFetcher({ redirectLocation: 'http://169.254.169.254/latest/meta-data' })
      )
    ).rejects.toThrow(/non-HTTPS|disallowed host/i);

    await expect(
      safeGitHubFetch(
        'https://api.github.com/repos/octo/demo/zipball/main',
        {},
        createMockGitHubFetcher({ redirectLocation: 'https://evil.example.com/archive.zip' })
      )
    ).rejects.toThrow(/disallowed host/i);

    const sawAuth = { value: false };
    const zipBytes = buildZipBuffer([{ name: 'octo-demo-123/app.py', content: 'print(1)\n' }]);
    const okRes = await safeGitHubFetch(
      'https://api.github.com/repos/octo/demo/zipball/main',
      { headers: { Authorization: 'Bearer secret-token' } },
      createMockGitHubFetcher({
        redirectLocation: 'https://codeload.github.com/octo/demo/legacy.zip/main',
        zipBuffer: zipBytes,
        sawAuthOnCdnRedirect: sawAuth,
      })
    );
    expect(okRes.status).toBe(200);
    expect(sawAuth.value).toBe(false);
  });

  it('supports student-scoped encrypted GitHub OAuth connect, private repo validation, and disconnect', async () => {
    const studentA = await registerStudent('Student A', 'gh-a@cse.edu');
    const studentB = await registerStudent('Student B', 'gh-b@cse.edu');

    // Unconnected validation against private repo fails clearly
    await expect(
      validateGitHubRepository({
        userId: studentA.user.id,
        repoUrl: 'https://github.com/octo/demo',
        fetchImpl: createMockGitHubFetcher({ requiresAuth: true, isPrivate: true }),
      })
    ).rejects.toThrow(/private|connect your github/i);

    // Complete OAuth for Student A
    const oauthInit = createGitHubOAuthUrl({ userId: studentA.user.id });
    expect(oauthInit.authUrl).toContain('https://github.com/login/oauth/authorize');

    const cb = await completeGitHubOAuthCallback({
      code: 'mock-code',
      state: oauthInit.state,
      callbackUrl: oauthInit.callbackUrl,
      fetchImpl: createMockGitHubFetcher({}),
    });
    expect(cb.githubUsername).toBe('octo-student');

    // Replay of single-use state fails
    await expect(
      completeGitHubOAuthCallback({
        code: 'mock-code',
        state: oauthInit.state,
        callbackUrl: oauthInit.callbackUrl,
        fetchImpl: createMockGitHubFetcher({}),
      })
    ).rejects.toThrow(/invalid or already used/i);

    // Token stored encrypted in DB (never plaintext)
    const row = getDb()
      .prepare('SELECT access_token_encrypted FROM github_connections WHERE user_id = ?')
      .get(studentA.user.id) as { access_token_encrypted: string };
    expect(row.access_token_encrypted).not.toContain('gho_mocked_secret_token_12345');
    expect(getUserGitHubAccessToken(studentA.user.id)).toBe('gho_mocked_secret_token_12345');

    // Student B remains disconnected & isolated
    expect(getGitHubConnectionStatus(studentB.user.id).connected).toBe(false);
    await expect(
      validateGitHubRepository({
        userId: studentB.user.id,
        repoUrl: 'https://github.com/octo/demo',
        fetchImpl: createMockGitHubFetcher({ requiresAuth: true, isPrivate: true }),
      })
    ).rejects.toThrow();

    // Student A can now validate the private repo
    const validated = await validateGitHubRepository({
      userId: studentA.user.id,
      repoUrl: 'https://github.com/octo/demo',
      branch: 'feature/auth',
      fetchImpl: createMockGitHubFetcher({ requiresAuth: true, isPrivate: true }),
    });
    expect(validated.isPrivate).toBe(true);
    expect(validated.selectedBranch).toBe('feature/auth');
    expect(validated.branches).toContain('feature/auth');

    // Disconnect removes token cleanly
    await disconnectGitHubConnection({
      userId: studentA.user.id,
      fetchImpl: createMockGitHubFetcher({}),
    });
    expect(getGitHubConnectionStatus(studentA.user.id).connected).toBe(false);
    expect(getUserGitHubAccessToken(studentA.user.id)).toBeNull();
  });

  it('rejects ZIP Slip traversal, symlinks, dangerous binaries, and leaves zero broken project records on failed imports', async () => {
    const student = await registerStudent('Zip Guard', 'zip-guard@cse.edu');

    // ZIP Slip path traversal
    const zipSlip = buildZipBuffer([{ name: 'octo-demo-123/../../etc/passwd', content: 'root:x:0:0' }]);
    await expect(
      importGitHubRepository({
        userId: student.user.id,
        repoUrl: 'https://github.com/octo/demo',
        fetchImpl: createMockGitHubFetcher({ zipBuffer: zipSlip }),
      })
    ).rejects.toThrow(/traversal/i);

    // Symlink inside archive
    const symlinkZip = buildZipBuffer([
      { name: 'octo-demo-123/link.py', content: '/etc/shadow', symlink: true },
    ]);
    await expect(
      importGitHubRepository({
        userId: student.user.id,
        repoUrl: 'https://github.com/octo/demo',
        fetchImpl: createMockGitHubFetcher({ zipBuffer: symlinkZip }),
      })
    ).rejects.toThrow(/symlink/i);

    // Dangerous executable
    const exeZip = buildZipBuffer([{ name: 'octo-demo-123/payload.exe', content: 'MZ' }]);
    await expect(
      importGitHubRepository({
        userId: student.user.id,
        repoUrl: 'https://github.com/octo/demo',
        fetchImpl: createMockGitHubFetcher({ zipBuffer: exeZip }),
      })
    ).rejects.toThrow(/executable|binary/i);

    // Verify no half-imported projects exist in DB
    const countRow = getDb()
      .prepare('SELECT COUNT(*) AS cnt FROM projects WHERE user_id = ?')
      .get(student.user.id) as { cnt: number };
    expect(countRow.cnt).toBe(0);
  });

  it('imports public repo, preserves historical scans across GitHub refresh, and recognizes all dependency manifests', async () => {
    const student = await registerStudent('Refresh Tester', 'refresh@cse.edu');
    const otherStudent = await registerStudent('Other Student', 'other-gh@cse.edu');

    const sha1 = '1111111111111111111111111111111111111111';
    const sha2 = '2222222222222222222222222222222222222222';

    const zipV1 = buildZipBuffer([
      {
        name: `octo-demo-${sha1}/app.py`,
        content: 'import sqlite3\ndef run(c, u):\n    c.execute("SELECT * FROM users WHERE id=" + u)\n',
      },
      {
        name: `octo-demo-${sha1}/pyproject.toml`,
        content: '[project]\nname = "demo"\ndependencies = ["flask==2.0.0"]\n',
      },
      {
        name: `octo-demo-${sha1}/pnpm-lock.yaml`,
        content: 'lockfileVersion: 6.0\n',
      },
    ]);

    const imported = await importGitHubRepository({
      userId: student.user.id,
      repoUrl: 'https://github.com/octo/demo',
      fetchImpl: createMockGitHubFetcher({ commitSha: sha1, zipBuffer: zipV1 }),
    });
    expect(imported.project.importMethod).toBe('github');
    expect(imported.project.githubCommitSha).toBe(sha1);
    expect(imported.project.githubBranch).toBe('main');
    expect(imported.importedFilesCount).toBe(3);

    // Run Scan 1 against SHA1
    const s1Res = await fetch(`${baseUrl}/api/scans`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: student.cookie,
        'X-CSRF-Token': student.csrfToken,
      },
      body: JSON.stringify({ projectId: imported.project.id, scanners: ['custom'] }),
    });
    expect(s1Res.status).toBe(201);
    const { scan: scan1 } = (await s1Res.json()) as {
      scan: { id: string; commitSha: string; totalFindings: number };
    };
    expect(scan1.commitSha).toBe(sha1);
    expect(scan1.totalFindings).toBeGreaterThanOrEqual(1);

    // Refresh when SHA unchanged -> changed: false
    const noChange = await refreshGitHubProject({
      userId: student.user.id,
      projectId: imported.project.id,
      fetchImpl: createMockGitHubFetcher({ commitSha: sha1, zipBuffer: zipV1 }),
    });
    expect(noChange.changed).toBe(false);

    // Refresh when SHA advances to SHA2 (vulnerability fixed in upstream commit)
    const zipV2 = buildZipBuffer([
      {
        name: `octo-demo-${sha2}/app.py`,
        content: 'import sqlite3\ndef run(c, u):\n    c.execute("SELECT * FROM users WHERE id=?", (u,))\n',
      },
      {
        name: `octo-demo-${sha2}/pyproject.toml`,
        content: '[project]\nname = "demo"\ndependencies = ["flask==3.0.0"]\n',
      },
    ]);
    const refreshed = await refreshGitHubProject({
      userId: student.user.id,
      projectId: imported.project.id,
      fetchImpl: createMockGitHubFetcher({ commitSha: sha2, zipBuffer: zipV2 }),
    });
    expect(refreshed.changed).toBe(true);
    expect(refreshed.previousCommitSha).toBe(sha1);
    expect(refreshed.latestCommitSha).toBe(sha2);

    // Historical scan1 findings & snapshots are still intact!
    const histRes = await fetch(`${baseUrl}/api/scans/${scan1.id}/findings`, {
      headers: { Cookie: student.cookie },
    });
    const histBody = (await histRes.json()) as { findings: Array<{ id: string }> };
    expect(histBody.findings).toHaveLength(scan1.totalFindings);

    // Student B cannot refresh Student A's GitHub project
    await expect(
      refreshGitHubProject({
        userId: otherStudent.user.id,
        projectId: imported.project.id,
        fetchImpl: createMockGitHubFetcher({ commitSha: sha2, zipBuffer: zipV2 }),
      })
    ).rejects.toThrow(/not found|access denied/i);

    // Verify all required manifest files are recognized
    for (const manifest of [
      'requirements.txt',
      'pyproject.toml',
      'Pipfile.lock',
      'poetry.lock',
      'package.json',
      'package-lock.json',
      'pnpm-lock.yaml',
      'yarn.lock',
      'Cargo.toml',
      'Cargo.lock',
      'go.mod',
      'go.sum',
      'pom.xml',
      'build.gradle',
      'build.gradle.kts',
      'Gemfile.lock',
    ]) {
      expect(detectFileLanguage(manifest).supported).toBe(true);
    }

    // Cancellation via AbortController aborts cleanly
    const abortCtrl = new AbortController();
    abortCtrl.abort();
    await expect(
      validateGitHubRepository({
        userId: student.user.id,
        repoUrl: 'https://github.com/octo/demo',
        signal: abortCtrl.signal,
        fetchImpl: createMockGitHubFetcher({}),
      })
    ).rejects.toThrow(/cancelled/i);

    expect(crypto.createHash('sha256').update('ok').digest('hex')).toBeTruthy();
  });

  it('standardizes AES-256-GCM token encryption and env validation on GITHUB_TOKEN_ENCRYPTION_KEY without breaking existing fallback credentials', () => {
    expect(GITHUB_TOKEN_ENCRYPTION_ENV_VAR).toBe('GITHUB_TOKEN_ENCRYPTION_KEY');

    const token = 'gho_existing_user_token_value';
    const ciphertext = encryptGitHubToken(token);
    const parts = ciphertext.split(':');
    expect(parts).toHaveLength(3);

    // Verify exact AES-256-GCM + SHA-256(GITHUB_TOKEN_ENCRYPTION_KEY) compatibility
    const expectedKey = crypto
      .createHash('sha256')
      .update(process.env.GITHUB_TOKEN_ENCRYPTION_KEY!)
      .digest();
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      expectedKey,
      Buffer.from(parts[0], 'base64')
    );
    decipher.setAuthTag(Buffer.from(parts[1], 'base64'));
    const plainFromDirectCrypto = Buffer.concat([
      decipher.update(Buffer.from(parts[2], 'base64')),
      decipher.final(),
    ]).toString('utf8');
    expect(plainFromDirectCrypto).toBe(token);
    expect(decryptGitHubToken(ciphertext)).toBe(token);

    // Valid env passes cleanly
    const validCheck = validateGitHubEnvironment();
    expect(validCheck.encryptionEnvVar).toBe('GITHUB_TOKEN_ENCRYPTION_KEY');
    expect(validCheck.encryptionKeyConfigured).toBe(true);
    expect(validCheck.legacyMisnamedEnvDetected).toBe(false);
    expect(validCheck.warnings).toHaveLength(0);

    // Setting mismatched GITHUB_TOKEN_ENCRYPTION triggers clear warning and is not used for encryption
    delete process.env.GITHUB_TOKEN_ENCRYPTION_KEY;
    process.env.GITHUB_TOKEN_ENCRYPTION = 'wrong-legacy-var-name';
    try {
      const legacyCheck = validateGitHubEnvironment();
      expect(legacyCheck.encryptionKeyConfigured).toBe(false);
      expect(legacyCheck.legacyMisnamedEnvDetected).toBe(true);
      expect(legacyCheck.warnings.some((w) => w.includes('GITHUB_TOKEN_ENCRYPTION_KEY'))).toBe(
        true
      );

      // Existing fallback encryption remains functional when GITHUB_TOKEN_ENCRYPTION_KEY is unset
      const fallbackCipher = encryptGitHubToken(token);
      expect(decryptGitHubToken(fallbackCipher)).toBe(token);
    } finally {
      delete process.env.GITHUB_TOKEN_ENCRYPTION;
    }
  });
});
