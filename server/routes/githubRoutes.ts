import { Router } from 'express';
import { requireAuth, requireCsrf, type AuthenticatedRequest } from '../auth/authMiddleware.ts';
import { FileSecurityError } from '../scanners/security/fileSecurity.ts';
import {
  completeGitHubOAuthCallback,
  createGitHubOAuthUrl,
  disconnectGitHubConnection,
  getGitHubCallbackUrl,
  getGitHubConnectionStatus,
  GitHubError,
} from '../github/githubOAuth.ts';
import {
  importGitHubRepository,
  refreshGitHubProject,
  validateGitHubRepository,
} from '../github/githubService.ts';

export const githubRoutes = Router();

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function renderOAuthPopupHtml(params: {
  ok: boolean;
  username?: string;
  error?: string;
  targetOrigin: string;
}): string {
  const payload = JSON.stringify(
    params.ok
      ? { type: 'GITHUB_OAUTH_SUCCESS', username: params.username || 'github-user' }
      : { type: 'GITHUB_OAUTH_ERROR', error: params.error || 'GitHub authorization failed.' }
  );

  const safeOrigin = JSON.stringify(params.targetOrigin);
  const messageText = params.ok
    ? `Connected GitHub account (${escapeHtml(params.username || '')}). This window will close automatically.`
    : escapeHtml(params.error || 'GitHub authorization failed.');

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>SecureLens — GitHub Connection</title>
    <style>
      body { font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
      .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 24px; max-width: 420px; text-align: center; }
      h1 { font-size: 16px; margin: 0 0 8px; }
      p { font-size: 13px; color: #cbd5e1; margin: 0; line-height: 1.5; }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>${params.ok ? 'GitHub Connected' : 'GitHub Connection Failed'}</h1>
      <p>${messageText}</p>
    </div>
    <script>
      try {
        if (window.opener) {
          window.opener.postMessage(${payload}, ${safeOrigin});
        }
      } catch (e) {}
      setTimeout(function () { window.close(); }, ${params.ok ? 800 : 3000});
    </script>
  </body>
</html>`;
}

// Public OAuth callback endpoint (matches both /api/github/oauth/callback and /api/github/oauth/callback/)
githubRoutes.get(['/oauth/callback', '/oauth/callback/'], async (req, res) => {
  const code = typeof req.query.code === 'string' ? req.query.code : '';
  const state = typeof req.query.state === 'string' ? req.query.state : '';
  const oauthErr = typeof req.query.error_description === 'string'
    ? req.query.error_description
    : typeof req.query.error === 'string'
      ? req.query.error
      : '';

  const callbackUrl = getGitHubCallbackUrl(req);
  const targetOrigin = new URL(callbackUrl).origin;

  if (oauthErr) {
    res
      .status(400)
      .type('html')
      .send(renderOAuthPopupHtml({ ok: false, error: oauthErr, targetOrigin }));
    return;
  }

  if (!code || !state) {
    res
      .status(400)
      .type('html')
      .send(
        renderOAuthPopupHtml({
          ok: false,
          error: 'Missing authorization code or state parameter from GitHub.',
          targetOrigin,
        })
      );
    return;
  }

  try {
    const result = await completeGitHubOAuthCallback({ code, state, callbackUrl });
    res
      .status(200)
      .type('html')
      .send(renderOAuthPopupHtml({ ok: true, username: result.githubUsername, targetOrigin }));
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'GitHub OAuth verification failed.';
    res.status(400).type('html').send(renderOAuthPopupHtml({ ok: false, error: msg, targetOrigin }));
  }
});

githubRoutes.use(requireAuth);

githubRoutes.get('/status', (req: AuthenticatedRequest, res) => {
  res.json({
    status: getGitHubConnectionStatus(req.auth!.userId),
    callbackUrl: getGitHubCallbackUrl(req),
  });
});

githubRoutes.get('/oauth/url', (req: AuthenticatedRequest, res) => {
  try {
    const { authUrl, callbackUrl } = createGitHubOAuthUrl({
      userId: req.auth!.userId,
      req,
    });
    res.json({ authUrl, callbackUrl });
  } catch (err) {
    if (err instanceof GitHubError) {
      res.status(err.statusCode).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: 'Failed to prepare GitHub OAuth URL.' });
  }
});

githubRoutes.use(requireCsrf);

githubRoutes.post('/disconnect', async (req: AuthenticatedRequest, res) => {
  await disconnectGitHubConnection({ userId: req.auth!.userId });
  res.json({ status: getGitHubConnectionStatus(req.auth!.userId) });
});

githubRoutes.post('/validate', async (req: AuthenticatedRequest, res) => {
  const { repoUrl, branch } = req.body || {};
  const controller = new AbortController();
  req.on('aborted', () => controller.abort());
  res.on('close', () => {
    if (!res.writableEnded) controller.abort();
  });

  try {
    const validation = await validateGitHubRepository({
      userId: req.auth!.userId,
      repoUrl: String(repoUrl || ''),
      branch: branch ? String(branch) : undefined,
      signal: controller.signal,
    });
    res.json({ validation });
  } catch (err) {
    if (err instanceof GitHubError || err instanceof FileSecurityError) {
      res.status(err.statusCode).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: 'Failed to validate GitHub repository.' });
  }
});

githubRoutes.post('/import', async (req: AuthenticatedRequest, res) => {
  const { repoUrl, branch, projectName, description, projectId } = req.body || {};
  const controller = new AbortController();
  req.on('aborted', () => controller.abort());
  res.on('close', () => {
    if (!res.writableEnded) controller.abort();
  });

  try {
    const result = await importGitHubRepository({
      userId: req.auth!.userId,
      projectId: projectId ? String(projectId) : undefined,
      projectName: projectName ? String(projectName) : undefined,
      description: description !== undefined ? String(description) : undefined,
      repoUrl: String(repoUrl || ''),
      branch: branch ? String(branch) : undefined,
      signal: controller.signal,
    });
    res.status(201).json(result);
  } catch (err) {
    if (err instanceof GitHubError || err instanceof FileSecurityError) {
      res.status(err.statusCode).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: 'Failed to import GitHub repository.' });
  }
});

githubRoutes.post('/projects/:id/refresh', async (req: AuthenticatedRequest, res) => {
  const controller = new AbortController();
  req.on('aborted', () => controller.abort());
  res.on('close', () => {
    if (!res.writableEnded) controller.abort();
  });

  try {
    const result = await refreshGitHubProject({
      userId: req.auth!.userId,
      projectId: String(req.params.id),
      signal: controller.signal,
    });
    res.json(result);
  } catch (err) {
    if (err instanceof GitHubError || err instanceof FileSecurityError) {
      res.status(err.statusCode).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: 'Failed to refresh repository from GitHub.' });
  }
});
