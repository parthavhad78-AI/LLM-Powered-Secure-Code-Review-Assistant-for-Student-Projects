import { spawn } from 'node:child_process';

export interface ProcessRunOptions {
  command: string;
  args: string[];
  cwd: string;
  timeoutMs?: number;
  signal?: AbortSignal;
  maxOutputBytes?: number;
}

export interface ProcessRunResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  cancelled: boolean;
  durationMs: number;
  spawnError?: string;
}

export function runSafeProcess(options: ProcessRunOptions): Promise<ProcessRunResult> {
  const {
    command,
    args,
    cwd,
    timeoutMs = 30000,
    signal,
    maxOutputBytes = 8 * 1024 * 1024,
  } = options;

  const startTime = Date.now();

  return new Promise((resolve) => {
    if (signal?.aborted) {
      resolve({
        exitCode: null,
        stdout: '',
        stderr: 'Cancelled before execution.',
        timedOut: false,
        cancelled: true,
        durationMs: 0,
      });
      return;
    }

    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let cancelled = false;
    let settled = false;

    const child = spawn(command, args, {
      cwd,
      shell: false,
      windowsHide: true,
      env: {
        ...process.env,
        PYTHONIOENCODING: 'utf-8',
      },
    });

    const killChild = () => {
      try {
        child.kill('SIGTERM');
        setTimeout(() => {
          if (!child.killed) {
            child.kill('SIGKILL');
          }
        }, 1500);
      } catch {
        // Ignore kill error if already exited
      }
    };

    const timer = setTimeout(() => {
      timedOut = true;
      killChild();
    }, timeoutMs);

    const onAbort = () => {
      cancelled = true;
      killChild();
    };
    signal?.addEventListener('abort', onAbort, { once: true });

    const cleanup = () => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
    };

    child.stdout?.on('data', (chunk: Buffer) => {
      if (stdout.length < maxOutputBytes) {
        stdout += chunk.toString('utf8');
      }
    });

    child.stderr?.on('data', (chunk: Buffer) => {
      if (stderr.length < maxOutputBytes) {
        stderr += chunk.toString('utf8');
      }
    });

    child.on('error', (err) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve({
        exitCode: null,
        stdout,
        stderr,
        timedOut,
        cancelled,
        durationMs: Date.now() - startTime,
        spawnError: err.message,
      });
    });

    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve({
        exitCode: code,
        stdout,
        stderr,
        timedOut,
        cancelled,
        durationMs: Date.now() - startTime,
      });
    });
  });
}
