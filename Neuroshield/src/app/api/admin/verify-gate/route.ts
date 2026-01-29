import { NextRequest, NextResponse } from 'next/server';

// Admin gate password - stored server-side only
const ADMIN_GATE_PASSWORD = process.env.ADMIN_GATE_PASSWORD || 'Jarrar@$26';

// Rate limiting configuration
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_ATTEMPTS_PER_WINDOW = 5;

// In-memory store for rate limiting (use Redis in production for multi-instance deployments)
const rateLimitStore = new Map<string, { attempts: number; windowStart: number }>();

// Clean up old entries periodically
const cleanupRateLimitStore = () => {
  const now = Date.now();
  for (const [ip, data] of rateLimitStore.entries()) {
    if (now - data.windowStart > RATE_LIMIT_WINDOW_MS) {
      rateLimitStore.delete(ip);
    }
  }
};

// Run cleanup every 5 minutes
setInterval(cleanupRateLimitStore, 5 * 60 * 1000);

const getClientIP = (request: NextRequest): string => {
  const forwarded = request.headers.get('x-forwarded-for');
  const realIP = request.headers.get('x-real-ip');
  return forwarded?.split(',')[0]?.trim() || realIP || 'unknown';
};

const checkRateLimit = (ip: string): { allowed: boolean; remainingAttempts: number; retryAfterMs?: number } => {
  const now = Date.now();
  const record = rateLimitStore.get(ip);

  if (!record || now - record.windowStart > RATE_LIMIT_WINDOW_MS) {
    // New window
    rateLimitStore.set(ip, { attempts: 1, windowStart: now });
    return { allowed: true, remainingAttempts: MAX_ATTEMPTS_PER_WINDOW - 1 };
  }

  if (record.attempts >= MAX_ATTEMPTS_PER_WINDOW) {
    const retryAfterMs = RATE_LIMIT_WINDOW_MS - (now - record.windowStart);
    return { allowed: false, remainingAttempts: 0, retryAfterMs };
  }

  record.attempts++;
  return { allowed: true, remainingAttempts: MAX_ATTEMPTS_PER_WINDOW - record.attempts };
};

export async function POST(request: NextRequest) {
  const clientIP = getClientIP(request);
  
  // Check rate limit
  const rateLimit = checkRateLimit(clientIP);
  
  if (!rateLimit.allowed) {
    const retryAfterSeconds = Math.ceil((rateLimit.retryAfterMs || 60000) / 1000);
    return NextResponse.json(
      { 
        success: false, 
        error: `Too many attempts. Please try again in ${retryAfterSeconds} seconds.` 
      },
      { 
        status: 429,
        headers: {
          'Retry-After': retryAfterSeconds.toString(),
          'X-RateLimit-Remaining': '0',
        }
      }
    );
  }

  try {
    const { password } = await request.json();

    if (!password) {
      return NextResponse.json(
        { success: false, error: 'Password is required' },
        { 
          status: 400,
          headers: { 'X-RateLimit-Remaining': rateLimit.remainingAttempts.toString() }
        }
      );
    }

    const isValid = password === ADMIN_GATE_PASSWORD;

    if (isValid) {
      return NextResponse.json(
        { success: true },
        { headers: { 'X-RateLimit-Remaining': rateLimit.remainingAttempts.toString() } }
      );
    } else {
      // Add delay on failed attempts to slow down brute force
      await new Promise(resolve => setTimeout(resolve, 1000));
      return NextResponse.json(
        { success: false, error: 'Invalid password' },
        { 
          status: 401,
          headers: { 'X-RateLimit-Remaining': rateLimit.remainingAttempts.toString() }
        }
      );
    }
  } catch (error) {
    console.error('[verify-gate] Error:', error);
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}
