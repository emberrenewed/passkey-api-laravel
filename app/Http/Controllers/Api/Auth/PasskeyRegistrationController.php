<?php

namespace App\Http\Controllers\Api\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\PasskeyRegisterOptionsRequest;
use App\Http\Requests\Auth\PasskeyRegisterVerifyRequest;
use App\Http\Resources\PasskeyCredentialResource;
use App\Models\User;
use App\Services\Auth\Passkey\PasskeyRegistrationService;
use App\Services\Auth\Passkey\TokenService;
use Illuminate\Http\JsonResponse;

class PasskeyRegistrationController extends Controller
{
    public function __construct(
        private PasskeyRegistrationService $registrationService,
        private TokenService $tokenService,
    ) {}

    /**
     * Generate WebAuthn registration options.
     *
     * POST /api/auth/passkey/register/options
     *
     * The frontend should pass these options to navigator.credentials.create()
     * after converting base64url fields to ArrayBuffer as needed.
     */
    public function options(PasskeyRegisterOptionsRequest $request): JsonResponse
    {
        $user = $this->resolveUser($request);

        $options = $this->registrationService->generateOptions($user, $request);

        return response()->json([
            'success' => true,
            'message' => 'Passkey registration options generated.',
            'data' => [
                'publicKey' => $options,
            ],
        ]);
    }

    /**
     * Verify a WebAuthn registration (attestation) response.
     *
     * POST /api/auth/passkey/register/verify
     *
     * After the user completes the WebAuthn ceremony in the browser,
     * the frontend sends the attestation response here for server-side verification.
     */
    public function verify(PasskeyRegisterVerifyRequest $request): JsonResponse
    {
        $user = $this->resolveUser($request);
        $validated = $request->validated();

        $credential = $this->registrationService->verify(
            user: $user,
            attestationData: $validated,
            request: $request,
            deviceName: $validated['device_name'] ?? null,
        );

        // Issue a token if the user doesn't have one yet (first passkey registration after signup).
        $tokenData = [];
        if (!$request->bearerToken()) {
            $token = $this->tokenService->createToken($user, 'passkey-registration');
            $tokenData = [
                'token' => $token,
                'token_type' => 'Bearer',
            ];
        }

        return response()->json([
            'success' => true,
            'message' => 'Passkey registered successfully.',
            'data' => array_filter([
                'passkey' => new PasskeyCredentialResource($credential),
                ...$tokenData,
            ]),
        ], 201);
    }

    /**
     * Generate options for adding an additional passkey (authenticated users).
     *
     * POST /api/auth/passkeys/add/options
     */
    public function addOptions(): JsonResponse
    {
        $user = request()->user();

        $options = $this->registrationService->generateOptions($user, request());

        return response()->json([
            'success' => true,
            'message' => 'Passkey registration options generated.',
            'data' => [
                'publicKey' => $options,
            ],
        ]);
    }

    /**
     * Verify an additional passkey registration (authenticated users).
     *
     * POST /api/auth/passkeys/add/verify
     */
    public function addVerify(PasskeyRegisterVerifyRequest $request): JsonResponse
    {
        $user = $request->user();
        $validated = $request->validated();

        $credential = $this->registrationService->verify(
            user: $user,
            attestationData: $validated,
            request: $request,
            deviceName: $validated['device_name'] ?? null,
        );

        return response()->json([
            'success' => true,
            'message' => 'Additional passkey registered successfully.',
            'data' => [
                'passkey' => new PasskeyCredentialResource($credential),
            ],
        ], 201);
    }

    /**
     * Resolve the user from the request.
     * Supports both user_id and email identification.
     */
    private function resolveUser($request): User
    {
        // If authenticated, use the authenticated user.
        if ($request->user()) {
            return $request->user();
        }

        if ($request->validated('user_id')) {
            return User::findOrFail($request->validated('user_id'));
        }

        return User::where('email', $request->validated('email'))->firstOrFail();
    }
}
