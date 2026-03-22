<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Middleware to ensure the passkey feature is enabled before processing requests.
 * Returns a clear error if passkeys are disabled via configuration.
 */
class EnsurePasskeyEnabled
{
    public function handle(Request $request, Closure $next): Response
    {
        if (!config('passkeys.enabled', true)) {
            return response()->json([
                'success' => false,
                'message' => 'Passkey authentication is not enabled on this server.',
                'error_code' => 'PASSKEY_BACKEND_DISABLED',
            ], 503);
        }

        return $next($request);
    }
}
