<?php

namespace App\Services\Auth\Passkey;

use App\Models\User;

/**
 * Manages Sanctum API token creation and revocation.
 */
class TokenService
{
    /**
     * Create a new Sanctum personal access token for the user.
     *
     * @param string $tokenName A descriptive name for the token (e.g., "passkey-auth", "password-auth").
     * @param array $abilities Token abilities/scopes. Default: all abilities.
     * @return string The plain-text token (only available at creation time).
     */
    public function createToken(User $user, string $tokenName = 'api-token', array $abilities = ['*']): string
    {
        return $user->createToken($tokenName, $abilities)->plainTextToken;
    }

    /**
     * Revoke the current token being used for this request.
     */
    public function revokeCurrentToken(User $user): void
    {
        $user->currentAccessToken()?->delete();
    }

    /**
     * Revoke all tokens for the user (e.g., for "logout everywhere").
     */
    public function revokeAllTokens(User $user): void
    {
        $user->tokens()->delete();
    }
}
