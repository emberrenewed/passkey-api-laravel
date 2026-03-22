<?php

namespace App\Http\Controllers\Api\Auth;

use App\Http\Controllers\Controller;
use App\Services\Auth\Passkey\PasskeySupportService;
use Illuminate\Http\JsonResponse;

class PasskeySupportController extends Controller
{
    public function __construct(
        private PasskeySupportService $supportService,
    ) {}

    /**
     * Return passkey support and configuration data for the frontend.
     *
     * GET /api/auth/passkey/support-check
     *
     * IMPORTANT: This endpoint returns backend configuration and guidance.
     * The backend CANNOT detect whether the user's browser or device supports
     * WebAuthn or has a platform authenticator. Actual browser/platform support
     * checks MUST be performed on the frontend. See the response for details.
     */
    public function __invoke(): JsonResponse
    {
        $supportData = $this->supportService->getSupportData();

        return response()->json([
            'success' => true,
            'data' => $supportData,
        ]);
    }
}
