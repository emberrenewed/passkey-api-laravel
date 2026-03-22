<?php

namespace App\Services\Auth\Passkey;

/**
 * Provides honest backend support/configuration metadata for frontends.
 *
 * IMPORTANT: The backend CANNOT reliably detect whether a user's browser or device
 * truly supports WebAuthn, platform authenticators, or specific biometric hardware.
 * Actual support detection MUST be done on the frontend/client side using:
 *
 * - window.PublicKeyCredential (basic WebAuthn support)
 * - PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable() (platform authenticator)
 * - PublicKeyCredential.isConditionalMediationAvailable() (autofill UI / conditional mediation)
 *
 * This service returns what the backend can provide:
 * - Whether the passkey feature is enabled
 * - The RP configuration the frontend needs
 * - Guidance for the frontend on what checks to perform
 *
 * The backend does NOT claim to know:
 * - Whether the user's device has a fingerprint reader
 * - Whether the user has Face ID
 * - Whether Windows Hello is configured
 * - Which specific authenticator will be used
 *
 * The device/OS/browser decides the authentication method (fingerprint, Face ID,
 * Windows Hello PIN, device passcode, etc.). This is correct WebAuthn behavior.
 */
class PasskeySupportService
{
    public function __construct(
        private WebAuthnConfigService $configService,
    ) {}

    /**
     * Get the support-check response data.
     */
    public function getSupportData(): array
    {
        return [
            'passkey_enabled' => $this->configService->isEnabled(),
            'rp' => [
                'id' => $this->configService->getRpId(),
                'name' => $this->configService->getRpName(),
            ],
            'allowed_origins' => $this->configService->getAllowedOrigins(),
            'preferences' => [
                'user_verification' => $this->configService->getUserVerification(),
                'resident_key' => $this->configService->getResidentKeyRequirement(),
                'attestation' => $this->configService->getAttestationConveyance(),
                'authenticator_attachment' => $this->configService->getAuthenticatorAttachment(),
                'timeout_ms' => $this->configService->getTimeoutMs(),
            ],
            'supported_flows' => [
                'discoverable_login' => $this->configService->getResidentKeyRequirement() !== 'discouraged',
                'email_first_login' => true,
            ],
            'frontend_checks_required' => [
                'description' => 'The backend cannot detect client-side WebAuthn support. '
                    . 'The frontend MUST perform these checks before initiating passkey flows.',
                'checks' => [
                    [
                        'name' => 'webauthn_available',
                        'js' => "typeof window.PublicKeyCredential !== 'undefined'",
                        'description' => 'Basic WebAuthn API availability in the browser.',
                    ],
                    [
                        'name' => 'platform_authenticator_available',
                        'js' => 'PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()',
                        'description' => 'Whether a platform authenticator (Touch ID, Windows Hello, etc.) is available. '
                            . 'Returns a Promise<boolean>.',
                    ],
                    [
                        'name' => 'conditional_mediation_available',
                        'js' => 'PublicKeyCredential.isConditionalMediationAvailable?.()',
                        'description' => 'Whether the browser supports conditional mediation (autofill UI for passkeys). '
                            . 'Returns a Promise<boolean>. Not available in all browsers.',
                    ],
                ],
            ],
            'notes' => [
                'The backend specifies the user_verification preference but does NOT control '
                    . 'how the user is verified. The device/OS chooses the method (fingerprint, '
                    . 'Face ID, Windows Hello PIN, device passcode, etc.).',
                'Devices without biometric hardware may still support passkeys through their '
                    . 'secure screen lock (PIN, pattern, or password). This is correct and expected.',
                'The authenticator_attachment preference is a hint, not a guarantee. The browser '
                    . 'may offer other authenticator types depending on the platform.',
            ],
        ];
    }
}
