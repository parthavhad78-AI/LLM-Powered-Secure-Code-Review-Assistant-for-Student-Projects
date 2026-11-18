import type { NextFunction, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import crypto from 'node:crypto';
import { getSessionByRawToken, type AuthSession } from './authService.ts';

export const SESSION_COOKIE_NAME = 'sl_session';

export interface AuthenticatedRequest extends Request {
  auth?: AuthSession;
}

export function getCookieOptions(req: Request): {
  httpOnly: boolean;
  sameSite: 'lax';
  secure: boolean;
  path: string;
  maxAge: number;
} {
  const isProd = process.env.NODE_ENV === 'production';
  const forwardedProto = req.headers['x-forwarded-proto'];
  const isHttps = req.secure || forwardedProto === 'https';

  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProd && isHttps,
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  };
}

export const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many authentication attempts. Please wait a few minutes and try again.',
  },
});

export const registerRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many registration requests from this address. Please try again later.',
  },
});

export function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const rawToken = req.cookies?.[SESSION_COOKIE_NAME];
  if (!rawToken || typeof rawToken !== 'string') {
    res.status(401).json({ error: 'Authentication required.' });
    return;
  }

  const session = getSessionByRawToken(rawToken);
  if (!session) {
    res.clearCookie(SESSION_COOKIE_NAME, { path: '/' });
    res.status(401).json({ error: 'Session expired or invalid. Please log in again.' });
    return;
  }

  req.auth = session;
  next();
}

export function requireCsrf(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
  if (safeMethods.includes(req.method.toUpperCase())) {
    next();
    return;
  }

  if (!req.auth) {
    res.status(401).json({ error: 'Authentication required.' });
    return;
  }

  const headerToken = req.headers['x-csrf-token'];
  if (!headerToken || typeof headerToken !== 'string') {
    res.status(403).json({ error: 'Missing CSRF protection token.' });
    return;
  }

  const expected = Buffer.from(req.auth.csrfToken, 'utf8');
  const provided = Buffer.from(headerToken, 'utf8');
  if (expected.length !== provided.length || !crypto.timingSafeEqual(expected, provided)) {
    res.status(403).json({ error: 'Invalid CSRF protection token.' });
    return;
  }

  next();
}
