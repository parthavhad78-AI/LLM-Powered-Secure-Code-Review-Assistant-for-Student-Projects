import 'dotenv/config';
import cookieParser from 'cookie-parser';
import express, { type NextFunction, type Request, type Response } from 'express';
import helmet from 'helmet';
import multer from 'multer';
import fs from 'node:fs';
import path from 'node:path';
import { initDatabase } from './server/database/db.ts';
import { validateGitHubEnvironment } from './server/github/githubOAuth.ts';
import { aiRoutes } from './server/routes/aiRoutes.ts';
import { authRoutes } from './server/routes/authRoutes.ts';
import { dashboardRoutes } from './server/routes/dashboardRoutes.ts';
import { findingRoutes } from './server/routes/findingRoutes.ts';
import { githubRoutes } from './server/routes/githubRoutes.ts';
import { learningRoutes } from './server/routes/learningRoutes.ts';
import { projectRoutes } from './server/routes/projectRoutes.ts';
import { reportRoutes } from './server/routes/reportRoutes.ts';
import { scannerRoutes, scanRoutes } from './server/routes/scanRoutes.ts';

export function createApp() {
  initDatabase();

  const app = express();
  app.set('trust proxy', 1);

  app.use(
    helmet({
      contentSecurityPolicy: false,
      frameguard: false,
      crossOriginEmbedderPolicy: false,
    })
  );

  app.use(cookieParser());
  app.use(express.json({ limit: '2mb' }));

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true, service: 'SecureLens' });
  });

  app.use('/api/auth', authRoutes);
  app.use('/api/dashboard', dashboardRoutes);
  app.use('/api/projects', projectRoutes);
  app.use('/api/github', githubRoutes);
  app.use('/api/scanners', scannerRoutes);
  app.use('/api/scans', scanRoutes);
  app.use('/api', findingRoutes);
  app.use('/api/ai', aiRoutes);
  app.use('/api/reports', reportRoutes);
  app.use('/api/learning', learningRoutes);

  // Global error handler (including multer file-size/limit errors)
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof multer.MulterError) {
      res.status(400).json({ error: `Upload error: ${err.message}` });
      return;
    }
    const status =
      typeof err === 'object' && err !== null && 'statusCode' in err
        ? Number((err as { statusCode: number }).statusCode)
        : 500;
    const message =
      err instanceof Error && status < 500
        ? err.message
        : 'An unexpected server error occurred.';
    res.status(status).json({ error: message });
  });

  return app;
}

async function startServer() {
  const ghEnv = validateGitHubEnvironment();
  for (const warning of ghEnv.warnings) {
    console.warn(`[SecureLens GitHub Config] ${warning}`);
  }

  const app = createApp();
  const isProd = process.env.NODE_ENV === 'production';

  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    if (fs.existsSync(distDir)) {
      app.use(express.static(distDir));
      app.get('*', (req, res, next) => {
        if (req.path.startsWith('/api/')) {
          next();
          return;
        }
        res.sendFile(path.join(distDir, 'index.html'));
      });
    }
  }

  const port = Number(process.env.PORT || 3000);
  app.listen(port, '0.0.0.0', () => {
    console.log(`SecureLens server listening on http://0.0.0.0:${port}`);
  });
}

// Start HTTP server only when executed directly (not when imported by Vitest)
const isTestEnv = Boolean(process.env.VITEST);
if (!isTestEnv) {
  startServer().catch((err) => {
    console.error('Failed to start SecureLens server:', err);
    process.exit(1);
  });
}
