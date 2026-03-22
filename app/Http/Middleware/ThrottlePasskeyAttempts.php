<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Cache\RateLimiter;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Rate limiting for passkey authentication endpoints.
 * Prevents brute-force attempts against the WebAuthn verification endpoints.
 */
class ThrottlePasskeyAttempts
{
    public function __construct(
        private RateLimiter $limiter,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $key = 'passkey:' . ($request->ip() ?? 'unknown');
        $maxAttempts = 10; // 10 attempts per minute
        $decayMinutes = 1;

        if ($this->limiter->tooManyAttempts($key, $maxAttempts)) {
            return response()->json([
                'success' => false,
                'message' => 'Too many authentication attempts. Please try again later.',
                'error_code' => 'RATE_LIMIT_EXCEEDED',
            ], 429);
        }

        $this->limiter->hit($key, $decayMinutes * 60);

        return $next($request);
    }
}
