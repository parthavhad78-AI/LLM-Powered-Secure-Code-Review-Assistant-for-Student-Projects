import { GoogleGenAI } from '@google/genai';

const ALLOWED_MODELS = new Set([
  'gemini-4-hydrogen',
  'gemini-3.1-flash-lite',
]);

export function getConfiguredGeminiModel(override?: string | null): string {
  const candidate = (override || process.env.GEMINI_MODEL || 'gemini-4-hydrogen').trim();
  if (ALLOWED_MODELS.has(candidate)) {
    return candidate;
  }
  return 'gemini-4-hydrogen';
}

export function isGeminiConfigured(): boolean {
  const key = process.env.GEMINI_API_KEY?.trim();
  return Boolean(key && key !== 'MY_GEMINI_API_KEY' && key.length > 10);
}

export function getGeminiStatus(): { configured: boolean; model: string } {
  return {
    configured: isGeminiConfigured(),
    model: getConfiguredGeminiModel(),
  };
}

export function createGeminiClient(): GoogleGenAI {
  const apiKey = process.env.GEMINI_API_KEY?.trim();
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
    throw new GeminiServiceError(
      'GEMINI_API_KEY is not configured on the server. Add it in Settings > Secrets.',
      503
    );
  }

  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

export async function withGeminiRetryAndTimeout<T>(
  operation: () => Promise<T>,
  timeoutMs = 25000,
  maxRetries = 2
): Promise<T> {
  let lastErr: unknown;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const timeoutPromise = new Promise<never>((_resolve, reject) => {
        setTimeout(() => reject(new GeminiServiceError('Gemini AI request timed out.', 504)), timeoutMs);
      });
      return await Promise.race([operation(), timeoutPromise]);
    } catch (err) {
      lastErr = err;
      const msg = err instanceof Error ? err.message : String(err);
      const isQuotaOrRate =
        msg.includes('429') ||
        msg.includes('RESOURCE_EXHAUSTED') ||
        msg.includes('503') ||
        msg.includes('UNAVAILABLE');

      if (msg.includes('API_KEY_INVALID') || msg.includes('PERMISSION_DENIED') || msg.includes('403')) {
        throw new GeminiServiceError(
          'Gemini API key was rejected or lacks permission. Please verify GEMINI_API_KEY in Settings > Secrets.',
          502
        );
      }

      if (attempt < maxRetries && isQuotaOrRate) {
        const backoffMs = 800 * Math.pow(2, attempt);
        await new Promise((r) => setTimeout(r, backoffMs));
        continue;
      }
      break;
    }
  }

  if (lastErr instanceof GeminiServiceError) {
    throw lastErr;
  }

  const message = lastErr instanceof Error ? lastErr.message : 'Gemini AI request failed.';
  if (message.includes('429') || message.includes('RESOURCE_EXHAUSTED')) {
    throw new GeminiServiceError(
      'Gemini API quota/rate limit reached. Please wait a moment and try again.',
      429
    );
  }
  throw new GeminiServiceError(`Gemini AI error: ${message}`, 502);
}

export class GeminiServiceError extends Error {
  statusCode: number;
  constructor(message: string, statusCode = 500) {
    super(message);
    this.name = 'GeminiServiceError';
    this.statusCode = statusCode;
  }
}
