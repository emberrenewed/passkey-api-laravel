<?php

namespace App\Http\Controllers\Api\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\PasswordLoginRequest;
use App\Http\Resources\UserResource;
use App\Models\AuditLog;
use App\Models\User;
use App\Services\Auth\Passkey\TokenService;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Hash;

/**
 * Optional backup password-based login controller.
 *
 * This is a BACKUP authentication method. The primary method is Passkey (WebAuthn).
 * Password login is provided for users who registered with a password as a fallback,
 * for example when accessing from a device that doesn't have their passkey.
 */
class LoginController extends Controller
{
    public function __construct(
        private TokenService $tokenService,
    ) {}

    /**
     * Authenticate with email and password (backup method).
     *
     * POST /api/auth/login/password
     */
    public function __invoke(PasswordLoginRequest $request): JsonResponse
    {
        $user = User::where('email', $request->validated('email'))->first();

        if (!$user || !$user->hasPassword() || !Hash::check($request->validated('password'), $user->password)) {
            AuditLog::logEvent(
                event: 'password.login.failed',
                userId: $user?->id,
                ipAddress: $request->ip(),
                userAgent: $request->userAgent(),
            );

            return response()->json([
                'success' => false,
                'message' => 'Invalid credentials.',
                'error_code' => 'INVALID_CREDENTIALS',
            ], 401);
        }

        $token = $this->tokenService->createToken($user, 'password-auth');

        AuditLog::logEvent(
            event: 'password.login.success',
            userId: $user->id,
            ipAddress: $request->ip(),
            userAgent: $request->userAgent(),
        );

        return response()->json([
            'success' => true,
            'message' => 'Authenticated successfully.',
            'data' => [
                'token' => $token,
                'token_type' => 'Bearer',
                'user' => new UserResource($user),
            ],
        ]);
    }
}
