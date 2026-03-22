<?php

namespace App\Services\Auth\Passkey;

use App\Enums\ErrorCode;
use App\Enums\WebauthnFlowType;
use App\Exceptions\ChallengeExpiredException;
use App\Exceptions\WebAuthnException;
use App\Models\WebauthnChallenge;
use Illuminate\Support\Str;

/**
 * Manages WebAuthn challenges with full security:
 * - Cryptographically secure random generation
 * - Time-limited validity (TTL)
 * - Single-use enforcement (replay protection)
 * - Server-side storage (challenges are never trusted from the client alone)
 * - Flow-type separation (registration vs authentication challenges cannot be mixed)
 */
class ChallengeService
{
    public function __construct(
        private WebAuthnConfigService $configService,
    ) {}

    /**
     * Generate a new cryptographically secure challenge.
     *
     * The challenge is stored server-side with a TTL. It must be verified
     * against the client's response to ensure the ceremony was initiated
     * by our server and not replayed from a previous session.
     */
    public function create(
        WebauthnFlowType $flowType,
        ?int $userId = null,
        ?array $context = null,
    ): WebauthnChallenge {
        // Generate 32 bytes of cryptographically secure random data,
        // then base64url-encode it for safe transport in JSON.
        $challengeBytes = random_bytes(32);
        $challenge = rtrim(strtr(base64_encode($challengeBytes), '+/', '-_'), '=');

        return WebauthnChallenge::create([
            'user_id' => $userId,
            'flow_type' => $flowType,
            'challenge' => $challenge,
            'expires_at' => now()->addSeconds($this->configService->getChallengeTtlSeconds()),
            'context' => $context,
        ]);
    }

    /**
     * Validate and consume a challenge.
     *
     * This method enforces ALL challenge security rules:
     * 1. The challenge must exist in our database (server-side verification)
     * 2. The flow type must match (registration challenge can't be used for auth)
     * 3. The challenge must not be expired (time-limited)
     * 4. The challenge must not have been already consumed (single-use / replay protection)
     *
     * After successful validation, the challenge is immediately marked as consumed
     * so it can never be reused.
     *
     * @throws WebAuthnException
     */
    public function validateAndConsume(
        string $challenge,
        WebauthnFlowType $expectedFlowType,
        ?int $expectedUserId = null,
    ): WebauthnChallenge {
        $record = WebauthnChallenge::where('challenge', $challenge)
            ->where('flow_type', $expectedFlowType)
            ->first();

        if (!$record) {
            throw new WebAuthnException(
                'Challenge not found or invalid.',
                ErrorCode::CHALLENGE_NOT_FOUND,
            );
        }

        // Verify user binding if applicable.
        // Registration challenges are bound to the user who initiated them.
        if ($expectedUserId !== null && $record->user_id !== null && $record->user_id !== $expectedUserId) {
            throw new WebAuthnException(
                'Challenge does not belong to this user.',
                ErrorCode::CHALLENGE_NOT_FOUND,
            );
        }

        if ($record->isConsumed()) {
            throw new WebAuthnException(
                'This challenge has already been used. Each challenge can only be used once.',
                ErrorCode::CHALLENGE_ALREADY_USED,
            );
        }

        if ($record->isExpired()) {
            throw new ChallengeExpiredException();
        }

        // Mark as consumed immediately - before any further processing.
        // This ensures the challenge cannot be reused even if verification fails later.
        $record->markConsumed();

        return $record;
    }

    /**
     * Purge expired challenges from the database.
     * Should be called periodically via a scheduled command.
     */
    public function purgeExpired(): int
    {
        return WebauthnChallenge::expired()->delete();
    }
}
