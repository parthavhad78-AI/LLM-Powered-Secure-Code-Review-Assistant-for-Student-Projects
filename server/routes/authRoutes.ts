import { Router } from 'express';
import {
  getCookieOptions,
  loginRateLimiter,
  registerRateLimiter,
  requireAuth,
  requireCsrf,
  SESSION_COOKIE_NAME,
  type AuthenticatedRequest,
} from '../auth/authMiddleware.ts';
import {
  AuthError,
  authenticateStudent,
  changeStudentPassword,
  createSession,
  deleteSessionByRawToken,
  registerStudent,
} from '../auth/authService.ts';
import { getDb } from '../database/db.ts';
import { getConfiguredGeminiModel } from '../ai/geminiClient.ts';

export const authRoutes = Router();

authRoutes.post('/register', registerRateLimiter, async (req, res) => {
  try {
    const { fullName, email, password, confirmPassword } = req.body || {};
    const user = await registerStudent({
      fullName: String(fullName || ''),
      email: String(email || ''),
      password: String(password || ''),
      confirmPassword: String(confirmPassword || ''),
    });

    const session = createSession(user.id, {
      userAgent: req.headers['user-agent'],
      ipAddress: req.ip,
    });

    res.cookie(SESSION_COOKIE_NAME, session.rawToken, getCookieOptions(req));
    res.status(201).json({
      user,
      csrfToken: session.csrfToken,
      expiresAt: session.expiresAt,
    });
  } catch (err) {
    if (err instanceof AuthError) {
      res.status(err.statusCode).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: 'Registration failed due to an internal error.' });
  }
});

authRoutes.post('/login', loginRateLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = await authenticateStudent({
      email: String(email || ''),
      password: String(password || ''),
    });

    const session = createSession(user.id, {
      userAgent: req.headers['user-agent'],
      ipAddress: req.ip,
    });

    res.cookie(SESSION_COOKIE_NAME, session.rawToken, getCookieOptions(req));
    res.json({
      user,
      csrfToken: session.csrfToken,
      expiresAt: session.expiresAt,
    });
  } catch (err) {
    if (err instanceof AuthError) {
      res.status(err.statusCode).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: 'Login failed due to an internal error.' });
  }
});

authRoutes.post('/logout', requireAuth, requireCsrf, (req: AuthenticatedRequest, res) => {
  const rawToken = req.cookies?.[SESSION_COOKIE_NAME];
  if (rawToken) {
    deleteSessionByRawToken(rawToken);
  }
  res.clearCookie(SESSION_COOKIE_NAME, { path: '/' });
  res.json({ ok: true });
});

authRoutes.get('/me', requireAuth, (req: AuthenticatedRequest, res) => {
  res.json({
    user: req.auth!.user,
    csrfToken: req.auth!.csrfToken,
    expiresAt: req.auth!.expiresAt,
  });
});

authRoutes.put('/profile', requireAuth, requireCsrf, (req: AuthenticatedRequest, res) => {
  const { fullName, preferredModel } = req.body || {};
  const cleanName = String(fullName || '').trim();
  if (cleanName.length < 2 || cleanName.length > 100) {
    res.status(400).json({ error: 'Full name must be between 2 and 100 characters.' });
    return;
  }

  const safeModel = getConfiguredGeminiModel(preferredModel ? String(preferredModel) : null);
  const db = getDb();
  const now = new Date().toISOString();

  db.prepare('UPDATE users SET full_name = ?, preferred_model = ?, updated_at = ? WHERE id = ?').run(
    cleanName,
    safeModel,
    now,
    req.auth!.userId
  );

  res.json({
    user: {
      ...req.auth!.user,
      fullName: cleanName,
      preferredModel: safeModel,
    },
  });
});

authRoutes.post('/change-password', requireAuth, requireCsrf, async (req: AuthenticatedRequest, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body || {};
    await changeStudentPassword(
      req.auth!.userId,
      String(currentPassword || ''),
      String(newPassword || ''),
      String(confirmPassword || '')
    );
    res.json({ ok: true, message: 'Password updated successfully.' });
  } catch (err) {
    if (err instanceof AuthError) {
      res.status(err.statusCode).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: 'Failed to update password.' });
  }
});
