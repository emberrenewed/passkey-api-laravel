<?php

namespace App\Http\Controllers\Api\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\PasskeyLoginOptionsRequest;
use App\Http\Requests\Auth\PasskeyLoginVerifyRequest;
use App\Http\Resources\UserResource;
use App\Services\Auth\Passkey\PasskeyAuthenticationService;
use Illuminate\Http\JsonResponse;

class PasskeyAuthenticationController extends Controller
{
    public function __construct(
        private PasskeyAuthenticationService $authenticationService,
    ) {}

    /**
     * Generate WebAuthn authentication options.
     *
     * POST /api/auth/passkey/login/options
     *
     * Supports two login strategies:
     *
     * 1. EMAIL-FIRST FLOW: Include "email" in the request body.
     *    The response will include allowCredentials with the user's registered credential IDs.
     *    The browser will only prompt for matching credentials.
     *
     * 2. DISCOVERABLE (USERNAME-LESS) FLOW: Omit "email" from the request.
     *    The response will NOT include allowCredentials.
     *    The authenticator will use a discoverable/resident credential.
     *    The user is identified by the userHandle in the assertion response.
     *
     * The frontend should pass these options to navigator.credentials.get()
     * after converting base64url fields to ArrayBuffer as needed.
     */
    public function options(PasskeyLoginOptionsRequest $request): JsonResponse
    {
        $options = $this->authenticationService->generateOptions(
            email: $request->validated('email'),
            request: $request,
        );

        return response()->json([
            'success' => true,
            'message' => 'Passkey authentication options generated.',
            'data' => [
                'publicKey' => $options,
            ],
        ]);
    }

    /**
     * Verify a WebAuthn authentication (assertion) response.
     *
     * POST /api/auth/passkey/login/verify
     *
     * After the user completes the WebAuthn ceremony in the browser,
     * the frontend sends the assertion response here for server-side verification.
     * On success, a Sanctum API token is issued.
     */
    public function verify(PasskeyLoginVerifyRequest $request): JsonResponse
    {
        $result = $this->authenticationService->verify(
            assertionData: $request->validated(),
            request: $request,
        );

        return response()->json([
            'success' => true,
            'message' => 'Authenticated successfully.',
            'data' => [
                'token' => $result['token'],
                'token_type' => $result['token_type'],
                'user' => new UserResource($result['user']),
            ],
        ]);
    }
}
