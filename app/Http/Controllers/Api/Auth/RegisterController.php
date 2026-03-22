<?php

namespace App\Http\Controllers\Api\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\RegisterRequest;
use App\Http\Resources\UserResource;
use App\Models\AuditLog;
use App\Models\User;
use Illuminate\Http\JsonResponse;

class RegisterController extends Controller
{
    /**
     * Register a new user account.
     *
     * POST /api/auth/register
     *
     * After registration, the frontend should prompt the user to register
     * a passkey using POST /api/auth/passkey/register/options.
     */
    public function __invoke(RegisterRequest $request): JsonResponse
    {
        $user = User::create([
            'name' => $request->validated('name'),
            'email' => $request->validated('email'),
            'password' => $request->validated('password')
                ? bcrypt($request->validated('password'))
                : null,
        ]);

        AuditLog::logEvent(
            event: 'user.registered',
            userId: $user->id,
            ipAddress: $request->ip(),
            userAgent: $request->userAgent(),
        );

        return response()->json([
            'success' => true,
            'message' => 'Account created successfully. Please register a passkey to secure your account.',
            'data' => [
                'user' => new UserResource($user),
            ],
        ], 201);
    }
}
