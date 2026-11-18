import AdmZip from 'adm-zip';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const MAX_SINGLE_FILE_BYTES = 2 * 1024 * 1024; // 2 MB
export const MAX_ARCHIVE_BYTES = 15 * 1024 * 1024; // 15 MB
export const MAX_EXTRACTED_TOTAL_BYTES = 30 * 1024 * 1024; // 30 MB
export const MAX_EXTRACTED_FILES = 300;
export const MAX_COMPRESSION_RATIO = 50;

const DANGEROUS_EXTENSIONS = new Set([
  '.exe',
  '.dll',
  '.so',
  '.dylib',
  '.bat',
  '.cmd',
  '.ps1',
  '.msi',
  '.bin',
  '.elf',
  '.com',
  '.vbs',
  '.scr',
  '.pif',
  '.jar',
  '.class',
  '.pyc',
  '.pyo',
  '.app',
  '.dmg',
  '.iso',
  '.deb',
  '.rpm',
]);

const SKIPPED_PATH_PREFIXES = ['__MACOSX/', '.git/', 'node_modules/', '.venv/', 'venv/', '__pycache__/'];

const EXTENSION_LANGUAGE_MAP: Record<string, { language: string; supported: boolean }> = {
  '.py': { language: 'Python', supported: true },
  '.js': { language: 'JavaScript', supported: true },
  '.jsx': { language: 'JavaScript', supported: true },
  '.mjs': { language: 'JavaScript', supported: true },
  '.cjs': { language: 'JavaScript', supported: true },
  '.ts': { language: 'TypeScript', supported: true },
  '.tsx': { language: 'TypeScript', supported: true },
  '.mts': { language: 'TypeScript', supported: true },
  '.cts': { language: 'TypeScript', supported: true },
  '.json': { language: 'JSON / Config', supported: true },
  '.txt': { language: 'Text / Manifest', supported: true },
  '.lock': { language: 'Lockfile', supported: true },
  '.toml': { language: 'TOML / Config', supported: true },
  '.xml': { language: 'XML / Manifest', supported: true },
  '.mod': { language: 'Go Module', supported: true },
  '.sum': { language: 'Go Checksum', supported: true },
  '.gradle': { language: 'Gradle Manifest', supported: true },
  '.kts': { language: 'Gradle Kotlin Manifest', supported: true },
  '.java': { language: 'Java', supported: false },
  '.c': { language: 'C', supported: false },
  '.h': { language: 'C/C++ Header', supported: false },
  '.cpp': { language: 'C++', supported: false },
  '.hpp': { language: 'C++ Header', supported: false },
  '.cc': { language: 'C++', supported: false },
  '.go': { language: 'Go', supported: false },
  '.rs': { language: 'Rust', supported: false },
  '.php': { language: 'PHP', supported: false },
  '.rb': { language: 'Ruby', supported: false },
  '.sql': { language: 'SQL', supported: false },
  '.yml': { language: 'YAML', supported: true },
  '.yaml': { language: 'YAML', supported: true },
  '.html': { language: 'HTML', supported: false },
  '.css': { language: 'CSS', supported: false },
  '.md': { language: 'Markdown', supported: false },
  '.env': { language: 'Environment Config', supported: true },
};

export class FileSecurityError extends Error {
  statusCode: number;
  constructor(message: string, statusCode = 400) {
    super(message);
    this.name = 'FileSecurityError';
    this.statusCode = statusCode;
  }
}

export function isDangerousExtension(fileName: string): boolean {
  const ext = path.extname(fileName).toLowerCase();
  return DANGEROUS_EXTENSIONS.has(ext);
}

export function detectFileLanguage(relativePath: string): { language: string; supported: boolean } {
  const base = path.basename(relativePath).toLowerCase();
  if (
    base === 'requirements.txt' ||
    base === 'pyproject.toml' ||
    base === 'pipfile.lock' ||
    base === 'poetry.lock' ||
    base === 'package.json' ||
    base === 'package-lock.json' ||
    base === 'pnpm-lock.yaml' ||
    base === 'yarn.lock' ||
    base === 'cargo.toml' ||
    base === 'cargo.lock' ||
    base === 'go.mod' ||
    base === 'go.sum' ||
    base === 'pom.xml' ||
    base === 'build.gradle' ||
    base === 'build.gradle.kts' ||
    base === 'gemfile.lock'
  ) {
    return { language: 'Dependency Manifest', supported: true };
  }
  if (base.startsWith('.env')) {
    return { language: 'Environment Config', supported: true };
  }
  const ext = path.extname(base);
  return EXTENSION_LANGUAGE_MAP[ext] ?? { language: 'Other', supported: false };
}

export function sanitizeRelativePath(rawEntryPath: string): string {
  if (!rawEntryPath || rawEntryPath.includes('\0')) {
    throw new FileSecurityError('Invalid file path containing null bytes or empty name.');
  }

  // Normalize Windows backslashes to forward slashes
  const unified = rawEntryPath.replace(/\\/g, '/').trim();

  if (unified.startsWith('/') || /^[A-Za-z]:/.test(unified)) {
    throw new FileSecurityError(`Unsafe absolute path rejected: ${rawEntryPath}`);
  }

  const segments = unified.split('/').filter((s) => s.length > 0 && s !== '.');
  if (segments.length === 0) {
    throw new FileSecurityError(`Invalid empty path: ${rawEntryPath}`);
  }

  for (const segment of segments) {
    if (segment === '..') {
      throw new FileSecurityError(`Path traversal attempt rejected: ${rawEntryPath}`);
    }
  }

  return segments.join('/');
}

export function assertPathInsideRoot(rootDir: string, targetPath: string): string {
  const resolvedRoot = path.resolve(rootDir);
  const resolvedTarget = path.resolve(resolvedRoot, targetPath);
  const rel = path.relative(resolvedRoot, resolvedTarget);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new FileSecurityError('Path traversal attempt detected outside project root.');
  }
  return resolvedTarget;
}

export interface StoredFileMeta {
  relativePath: string;
  language: string;
  sizeBytes: number;
  sha256: string;
  isSupported: boolean;
}

export function getProjectStorageRoot(userId: string, projectId: string): string {
  const baseDataDir = path.resolve(process.cwd(), 'data', 'projects');
  const safeUser = userId.replace(/[^a-zA-Z0-9_-]/g, '');
  const safeProj = projectId.replace(/[^a-zA-Z0-9_-]/g, '');
  if (!safeUser || !safeProj) {
    throw new FileSecurityError('Invalid project ownership identifier.');
  }
  return path.join(baseDataDir, safeUser, safeProj);
}

export function getProjectSourceDir(userId: string, projectId: string): string {
  return path.join(getProjectStorageRoot(userId, projectId), 'source');
}

export function getProjectBackupDir(userId: string, projectId: string): string {
  return path.join(getProjectStorageRoot(userId, projectId), 'backups');
}

function shouldSkipArchivePath(normalizedPath: string): boolean {
  return SKIPPED_PATH_PREFIXES.some(
    (prefix) => normalizedPath.startsWith(prefix) || normalizedPath.includes(`/${prefix}`)
  );
}

export function safeExtractZipToProject(zipBuffer: Buffer, destSourceDir: string): StoredFileMeta[] {
  if (zipBuffer.length > MAX_ARCHIVE_BYTES) {
    throw new FileSecurityError(
      `ZIP archive exceeds maximum allowed size of ${MAX_ARCHIVE_BYTES / (1024 * 1024)} MB.`
    );
  }

  let zip: AdmZip;
  try {
    zip = new AdmZip(zipBuffer);
  } catch {
    throw new FileSecurityError('Corrupted or invalid ZIP archive.');
  }

  const entries = zip.getEntries();
  if (entries.length === 0) {
    throw new FileSecurityError('ZIP archive is empty.');
  }

  let totalExtractedBytes = 0;
  const extractedFiles: Array<{ relPath: string; content: Buffer }> = [];

  for (const entry of entries) {
    const rawName = entry.entryName;
    if (rawName.includes('\0')) {
      throw new FileSecurityError('Archive contains invalid null-byte entry.');
    }

    // Reject symlinks via external attributes (Unix symlink mode 0120000)
    const unixMode = (entry.header.attr >>> 16) & 0o170000;
    if (unixMode === 0o120000) {
      throw new FileSecurityError(`Archive contains disallowed symlink: ${rawName}`);
    }

    if (entry.isDirectory) {
      // Still validate path traversal on directory entries
      sanitizeRelativePath(rawName.replace(/\/+$/, '') || 'dir');
      continue;
    }

    const relPath = sanitizeRelativePath(rawName);
    if (shouldSkipArchivePath(relPath)) {
      continue;
    }

    if (isDangerousExtension(relPath)) {
      throw new FileSecurityError(`Disallowed executable or binary file in archive: ${relPath}`);
    }

    const uncompressedSize = entry.header.size;
    const compressedSize = entry.header.compressedSize;

    if (uncompressedSize > MAX_SINGLE_FILE_BYTES) {
      throw new FileSecurityError(`File "${relPath}" exceeds maximum single file size (2 MB).`);
    }

    if (compressedSize > 1024 && uncompressedSize / compressedSize > MAX_COMPRESSION_RATIO) {
      throw new FileSecurityError(
        `Suspicious compression ratio detected in "${relPath}" (possible archive bomb).`
      );
    }

    totalExtractedBytes += uncompressedSize;
    if (totalExtractedBytes > MAX_EXTRACTED_TOTAL_BYTES) {
      throw new FileSecurityError('Extracted archive contents exceed maximum allowed limit (30 MB).');
    }

    if (extractedFiles.length >= MAX_EXTRACTED_FILES) {
      throw new FileSecurityError(`Archive exceeds maximum allowed file count (${MAX_EXTRACTED_FILES}).`);
    }

    const content = entry.getData();
    if (content.length > MAX_SINGLE_FILE_BYTES) {
      throw new FileSecurityError(`Extracted file "${relPath}" exceeds size limit.`);
    }

    extractedFiles.push({ relPath, content });
  }

  if (extractedFiles.length === 0) {
    throw new FileSecurityError('No eligible source files found inside ZIP archive.');
  }

  // Strip common single top-level wrapper folder if every file shares it (e.g. my-repo-main/...)
  const firstSegments = new Set(
    extractedFiles.map((f) => (f.relPath.includes('/') ? f.relPath.split('/')[0] : ''))
  );
  const stripPrefix =
    firstSegments.size === 1 && !firstSegments.has('')
      ? `${Array.from(firstSegments)[0]}/`
      : '';

  fs.mkdirSync(destSourceDir, { recursive: true });
  const stored: StoredFileMeta[] = [];

  for (const item of extractedFiles) {
    const finalRelPath =
      stripPrefix && item.relPath.startsWith(stripPrefix)
        ? item.relPath.slice(stripPrefix.length)
        : item.relPath;

    if (!finalRelPath) continue;
    const absTarget = assertPathInsideRoot(destSourceDir, finalRelPath);
    fs.mkdirSync(path.dirname(absTarget), { recursive: true });
    fs.writeFileSync(absTarget, item.content);

    const { language, supported } = detectFileLanguage(finalRelPath);
    const sha256 = crypto.createHash('sha256').update(item.content).digest('hex');

    stored.push({
      relativePath: finalRelPath,
      language,
      sizeBytes: item.content.length,
      sha256,
      isSupported: supported,
    });
  }

  return stored;
}

export function safeStoreUploadedFiles(
  files: Array<{ originalname: string; buffer: Buffer }>,
  destSourceDir: string
): StoredFileMeta[] {
  if (files.length === 0) {
    throw new FileSecurityError('No files were uploaded.');
  }
  if (files.length > MAX_EXTRACTED_FILES) {
    throw new FileSecurityError(`Too many files uploaded (max ${MAX_EXTRACTED_FILES}).`);
  }

  let totalBytes = 0;
  for (const file of files) {
    if (file.buffer.length > MAX_SINGLE_FILE_BYTES) {
      throw new FileSecurityError(`File "${file.originalname}" exceeds 2 MB limit.`);
    }
    totalBytes += file.buffer.length;
    if (totalBytes > MAX_EXTRACTED_TOTAL_BYTES) {
      throw new FileSecurityError('Total upload size exceeds 30 MB limit.');
    }
  }

  fs.mkdirSync(destSourceDir, { recursive: true });
  const stored: StoredFileMeta[] = [];

  for (const file of files) {
    const relPath = sanitizeRelativePath(file.originalname);
    if (isDangerousExtension(relPath)) {
      throw new FileSecurityError(`Disallowed dangerous file type: ${relPath}`);
    }

    const absTarget = assertPathInsideRoot(destSourceDir, relPath);
    fs.mkdirSync(path.dirname(absTarget), { recursive: true });
    fs.writeFileSync(absTarget, file.buffer);

    const { language, supported } = detectFileLanguage(relPath);
    const sha256 = crypto.createHash('sha256').update(file.buffer).digest('hex');
    stored.push({
      relativePath: relPath,
      language,
      sizeBytes: file.buffer.length,
      sha256,
      isSupported: supported,
    });
  }

  return stored;
}

export function collectDirectoryFiles(rootDir: string): string[] {
  if (!fs.existsSync(rootDir)) return [];
  const results: string[] = [];

  function walk(currentDir: string): void {
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (['node_modules', '.git', '__pycache__', '.venv', 'venv'].includes(entry.name)) {
          continue;
        }
        walk(fullPath);
      } else if (entry.isFile()) {
        const rel = path.relative(rootDir, fullPath).replace(/\\/g, '/');
        results.push(rel);
      }
    }
  }

  walk(rootDir);
  return results.sort();
}

export function createTempScanWorkspace(scanId: string, sourceDir: string): string {
  const tempDir = path.resolve(process.cwd(), 'temp_scans', scanId.replace(/[^a-zA-Z0-9_-]/g, ''));
  fs.rmSync(tempDir, { recursive: true, force: true });
  fs.mkdirSync(tempDir, { recursive: true });

  const files = collectDirectoryFiles(sourceDir);
  for (const rel of files) {
    const src = assertPathInsideRoot(sourceDir, rel);
    const dst = assertPathInsideRoot(tempDir, rel);
    fs.mkdirSync(path.dirname(dst), { recursive: true });
    fs.copyFileSync(src, dst);
  }
  return tempDir;
}

export function cleanupTempDir(tempDir: string): void {
  try {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  } catch {
    // Best-effort cleanup
  }
}
