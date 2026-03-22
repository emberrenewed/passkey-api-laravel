<?php

namespace App\Services\Auth\Passkey;

use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use App\Models\User;

/**
 * Centralized WebAuthn configuration provider.
 *
 * All RP (Relying Party) configuration, user verification preferences,
 * and timeout settings are sourced from config/passkeys.php, which reads
 * from environment variables. This ensures consistent behavior across
 * all WebAuthn ceremonies.
 */
class WebAuthnConfigService
{
    public function getRpId(): string
    {
        return config('passkeys.rp_id');
    }

    public function getRpName(): string
    {
        return config('passkeys.rp_name');
    }

    public function getRpEntity(): PublicKeyCredentialRpEntity
    {
        return PublicKeyCredentialRpEntity::create(
            name: $this->getRpName(),
            id: $this->getRpId(),
        );
    }

    public function getUserEntity(User $user): PublicKeyCredentialUserEntity
    {
        return PublicKeyCredentialUserEntity::create(
            name: $user->email,
            id: $user->getWebAuthnUserHandle(),
            displayName: $user->name,
        );
    }

    public function getAllowedOrigins(): array
    {
        return config('passkeys.allowed_origins', []);
    }

    public function getTimeoutMs(): int
    {
        return config('passkeys.timeout_ms', 60000);
    }

    public function getChallengeTtlSeconds(): int
    {
        return config('passkeys.challenge_ttl', 300);
    }

    /**
     * User verification preference.
     *
     * IMPORTANT: This setting tells the authenticator WHETHER to verify the user,
     * not HOW. The actual verification method (fingerprint, Face ID, Windows Hello PIN,
     * device passcode, etc.) is entirely determined by the device/OS/browser.
     *
     * The backend CANNOT and SHOULD NOT attempt to detect or control the specific
     * biometric or authentication method used. This is the correct and secure
     * WebAuthn behavior.
     */
    public function getUserVerification(): string
    {
        return config('passkeys.user_verification', 'preferred');
    }

    public function getResidentKeyRequirement(): string
    {
        return config('passkeys.resident_key', 'required');
    }

    public function getAttestationConveyance(): string
    {
        return config('passkeys.attestation', 'none');
    }

    public function getAuthenticatorAttachment(): ?string
    {
        return config('passkeys.authenticator_attachment');
    }

    public function isEnabled(): bool
    {
        return config('passkeys.enabled', true);
    }

    public function isStrictOrigin(): bool
    {
        return config('passkeys.strict_origin', true);
    }
}
