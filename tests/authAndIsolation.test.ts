import AdmZip from 'adm-zip';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  AuthError,
  authenticateStudent,
  createSession,
  deleteSessionByRawToken,
  getSessionByRawToken,
  registerStudent,
} from '../server/auth/authService.ts';
import { closeDb, initDatabase } from '../server/database/db.ts';
import {
  FileSecurityError,
  safeExtractZipToProject,
  safeStoreUploadedFiles,
} from '../server/scanners/security/fileSecurity.ts';

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sl-auth-test-'));
  initDatabase(path.join(tmpDir, 'test.db'));
});

afterEach(() => {
  closeDb();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe('Student Authentication & Sessions', () => {
  it('registers a student, hashes password with bcrypt, and rejects duplicate email', async () => {
    const user = await registerStudent({
      fullName: 'Priya Nair',
      email: 'priya@cse.edu',
      password: 'Password123!',
      confirmPassword: 'Password123!',
    });

    expect(user.email).toBe('priya@cse.edu');
    expect(user.fullName).toBe('Priya Nair');

    await expect(
      registerStudent({
        fullName: 'Priya Duplicate',
        email: 'PRIYA@cse.edu',
        password: 'Password123!',
        confirmPassword: 'Password123!',
      })
    ).rejects.toThrow(AuthError);
  });

  it('enforces password strength and matching confirmation', async () => {
    await expect(
      registerStudent({
        fullName: 'Test Student',
        email: 'weak@cse.edu',
        password: 'short',
        confirmPassword: 'short',
      })
    ).rejects.toThrow('at least 8 characters');

    await expect(
      registerStudent({
        fullName: 'Test Student',
        email: 'mismatch@cse.edu',
        password: 'Password123!',
        confirmPassword: 'Different123!',
      })
    ).rejects.toThrow('do not match');
  });

  it('authenticates valid credentials, creates persistent session, and supports logout', async () => {
    const user = await registerStudent({
      fullName: 'Rohan Verma',
      email: 'rohan@cse.edu',
      password: 'SecurePass99!',
      confirmPassword: 'SecurePass99!',
    });

    await expect(
      authenticateStudent({ email: 'rohan@cse.edu', password: 'WrongPassword!' })
    ).rejects.toThrow('Invalid email or password');

    const authed = await authenticateStudent({
      email: 'rohan@cse.edu',
      password: 'SecurePass99!',
    });
    expect(authed.id).toBe(user.id);

    const session = createSession(authed.id);
    const loaded = getSessionByRawToken(session.rawToken);
    expect(loaded).not.toBeNull();
    expect(loaded?.userId).toBe(user.id);
    expect(loaded?.csrfToken).toBe(session.csrfToken);

    deleteSessionByRawToken(session.rawToken);
    expect(getSessionByRawToken(session.rawToken)).toBeNull();
  });
});

describe('File Upload & ZIP Security', () => {
  it('blocks dangerous executable uploads', () => {
    const dest = path.join(tmpDir, 'proj_source');
    expect(() =>
      safeStoreUploadedFiles(
        [{ originalname: 'malware.exe', buffer: Buffer.from('MZ') }],
        dest
      )
    ).toThrow(FileSecurityError);
  });

  it('prevents ZIP Slip path traversal and extracts safe source files cleanly', () => {
    const zip = new AdmZip();
    zip.addFile('passwd', Buffer.from('root:x:0:0'));
    zip.getEntries()[0].entryName = '../../etc/passwd';
    const dest = path.join(tmpDir, 'zip_evil');

    expect(() => safeExtractZipToProject(zip.toBuffer(), dest)).toThrow('Path traversal');

    const safeZip = new AdmZip();
    safeZip.addFile('my-app/app.py', Buffer.from('print("hello")\n'));
    safeZip.addFile('my-app/requirements.txt', Buffer.from('flask==3.0.0\n'));
    const destSafe = path.join(tmpDir, 'zip_safe');
    const meta = safeExtractZipToProject(safeZip.toBuffer(), destSafe);

    expect(meta).toHaveLength(2);
    expect(meta.map((m) => m.relativePath)).toContain('app.py');
    expect(fs.existsSync(path.join(destSafe, 'app.py'))).toBe(true);
  });
});
