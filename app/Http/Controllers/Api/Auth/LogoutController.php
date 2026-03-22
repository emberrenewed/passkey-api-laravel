<?php

namespace App\Http\Controllers\Api\Auth;

use App\Http\Controllers\Controller;
use App\Models\AuditLog;
use App\Services\Auth\Passkey\TokenService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class LogoutController extends Controller
{
    public function __construct(
        private TokenService $tokenService,
    ) {}

    /**
     * Revoke the current API token (logout).
     *
     * POST /api/auth/logout
     */
    public function __invoke(Request $request): JsonResponse
    {
        $user = $request->user();

        $this->tokenService->revokeCurrentToken($user);

        AuditLog::logEvent(
            event: 'user.logout',
            userId: $user->id,
            ipAddress: $request->ip(),
            userAgent: $request->userAgent(),
        );

        return response()->json([
            'success' => true,
            'message' => 'Logged out successfully.',
        ]);
    }
}
