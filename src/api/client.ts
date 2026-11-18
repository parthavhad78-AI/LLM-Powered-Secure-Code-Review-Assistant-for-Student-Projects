let csrfTokenMemory: string | null = null;

export function setCsrfToken(token: string | null): void {
  csrfTokenMemory = token;
}

export function getCsrfToken(): string | null {
  return csrfTokenMemory;
}

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

export async function apiRequest<T>(
  url: string,
  options: RequestInit = {}
): Promise<T> {
  const method = (options.method || 'GET').toUpperCase();
  const headers = new Headers(options.headers || {});

  if (!(options.body instanceof FormData) && !headers.has('Content-Type') && method !== 'GET' && method !== 'HEAD') {
    headers.set('Content-Type', 'application/json');
  }

  if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && csrfTokenMemory) {
    headers.set('X-CSRF-Token', csrfTokenMemory);
  }

  const response = await fetch(url, {
    ...options,
    headers,
    credentials: 'include',
  });

  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const payload = await response.json();
      if (payload?.error) message = String(payload.error);
    } catch {
      // Ignore JSON parse failure
    }
    if (
      response.status === 401 &&
      typeof window !== 'undefined' &&
      !url.includes('/api/auth/login') &&
      !url.includes('/api/auth/register') &&
      !url.includes('/api/auth/me')
    ) {
      window.dispatchEvent(
        new CustomEvent('securelens:auth-expired', {
          detail: { message },
        })
      );
    }
    throw new ApiError(message, response.status);
  }

  if (response.status === 204) {
    return {} as T;
  }

  return (await response.json()) as T;
}
