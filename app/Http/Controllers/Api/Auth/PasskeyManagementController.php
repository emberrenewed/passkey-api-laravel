<?php

namespace App\Http\Controllers\Api\Auth;

use App\Enums\ErrorCode;
use App\Exceptions\WebAuthnException;
use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\RenamePasskeyRequest;
use App\Http\Resources\PasskeyCredentialResource;
use App\Models\AuditLog;
use App\Models\PasskeyCredential;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class PasskeyManagementController extends Controller
{
    /**
     * List all passkeys for the authenticated user.
     *
     * GET /api/auth/passkeys
     */
    public function index(Request $request): JsonResponse
    {
        $passkeys = $request->user()
            ->activePasskeyCredentials()
            ->orderBy('created_at', 'desc')
            ->get();

        return response()->json([
            'success' => true,
            'data' => [
                'passkeys' => PasskeyCredentialResource::collection($passkeys),
            ],
        ]);
    }

    /**
     * Rename a passkey's device name.
     *
     * PATCH /api/auth/passkeys/{id}
     */
    public function update(RenamePasskeyRequest $request, int $id): JsonResponse
    {
        $passkey = $this->resolvePasskey($request, $id);

        $passkey->update([
            'device_name' => $request->validated('device_name'),
        ]);

        return response()->json([
            'success' => true,
            'message' => 'Passkey renamed successfully.',
            'data' => [
                'passkey' => new PasskeyCredentialResource($passkey->fresh()),
            ],
        ]);
    }

    /**
     * Delete (soft-delete) a passkey.
     *
     * DELETE /api/auth/passkeys/{id}
     *
     * Business rule: If this is the user's last passkey and they have no password set,
     * deletion is prevented to avoid locking the user out of their account.
     */
    public function destroy(Request $request, int $id): JsonResponse
    {
        $passkey = $this->resolvePasskey($request, $id);
        $user = $request->user();

        // Prevent deletion of the last credential if no backup auth method exists.
        $remainingCredentials = $user->activePasskeyCredentials()->count();
        if ($remainingCredentials <= 1 && !$user->hasPassword()) {
            throw new WebAuthnException(
                'Cannot delete your last passkey without an alternative authentication method. '
                    . 'Please set a password or register another passkey first.',
                ErrorCode::LAST_PASSKEY_DELETION_NOT_ALLOWED,
                409,
            );
        }

        // Soft-delete to allow potential recovery and audit trail.
        $passkey->delete();

        AuditLog::logEvent(
            event: 'passkey.deleted',
            userId: $user->id,
            ipAddress: $request->ip(),
            userAgent: $request->userAgent(),
            metadata: [
                'passkey_id' => $id,
                'device_name' => $passkey->device_name,
            ],
        );

        return response()->json([
            'success' => true,
            'message' => 'Passkey deleted successfully.',
        ]);
    }

    /**
     * Resolve and authorize access to a passkey.
     * Ensures the passkey belongs to the authenticated user.
     */
    private function resolvePasskey(Request $request, int $id): PasskeyCredential
    {
        $passkey = PasskeyCredential::where('id', $id)
            ->where('user_id', $request->user()->id)
            ->whereNull('deleted_at')
            ->first();

        if (!$passkey) {
            throw new WebAuthnException(
                'Passkey not found.',
                ErrorCode::CREDENTIAL_NOT_FOUND,
                404,
            );
        }

        return $passkey;
    }
}
