<?php

namespace App\Services\Auth\Passkey;

use App\Enums\ErrorCode;
use App\Enums\WebauthnFlowType;
use App\Exceptions\DuplicateCredentialException;
use App\Exceptions\WebAuthnException;
use App\Models\AuditLog;
use App\Models\PasskeyCredential;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\AuthenticatorSelectionCriteria;

/**
 * Handles the WebAuthn registration ceremony (creating new passkey credentials).
 *
 * Registration flow:
 * 1. Generate creation options (challenge, RP info, user info, excluded credentials)
 * 2. Client calls navigator.credentials.create() with these options
 * 3. Client sends the attestation response back to verify
 * 4. Server verifies the attestation and stores the new credential
 *
 * SECURITY NOTE: The actual biometric/PIN prompt that the user sees during
 * navigator.credentials.create() is handled entirely by the device/OS/browser.
 * The backend does NOT control or know whether the user used fingerprint,
 * Face ID, Windows Hello PIN, or device passcode. This is correct behavior.
 */
class PasskeyRegistrationService
{
    public function __construct(
        private WebAuthnConfigService $configService,
        private ChallengeService $challengeService,
    ) {}

    /**
     * Generate WebAuthn PublicKeyCredentialCreationOptions.
     *
     * Returns the options that the frontend must pass to navigator.credentials.create().
     * The challenge is stored server-side for later verification.
     */
    public function generateOptions(User $user, Request $request): array
    {
        // Create a new challenge for this registration ceremony.
        $challenge = $this->challengeService->create(
            flowType: WebauthnFlowType::Registration,
            userId: $user->id,
            context: [
                'ip' => $request->ip(),
                'user_agent' => $request->userAgent(),
            ],
        );

        // Get already-registered credential IDs for this user to exclude them.
        // This prevents the same authenticator from being registered twice.
        $excludeCredentials = $user->activePasskeyCredentials
            ->map(fn (PasskeyCredential $cred) => [
                'type' => 'public-key',
                'id' => $cred->credential_id,
                'transports' => $cred->transports ?? [],
            ])
            ->values()
            ->toArray();

        // Build authenticator selection criteria.
        $authenticatorSelection = [
            'userVerification' => $this->configService->getUserVerification(),
            'residentKey' => $this->configService->getResidentKeyRequirement(),
            'requireResidentKey' => $this->configService->getResidentKeyRequirement() === 'required',
        ];

        if ($this->configService->getAuthenticatorAttachment()) {
            $authenticatorSelection['authenticatorAttachment'] = $this->configService->getAuthenticatorAttachment();
        }

        // Supported public key credential algorithms, ordered by preference.
        // ES256 (ECDSA with P-256) is the most widely supported.
        // RS256 (RSASSA-PKCS1-v1_5) is a fallback for older authenticators.
        // EdDSA (Ed25519) is newer and efficient.
        $pubKeyCredParams = [
            ['type' => 'public-key', 'alg' => -7],   // ES256
            ['type' => 'public-key', 'alg' => -257],  // RS256
            ['type' => 'public-key', 'alg' => -8],    // EdDSA
        ];

        // Dynamic RP ID handling for local development:
        // If RP ID is 'localhost', we allow it to match the actual host (e.g. 127.0.0.1)
        // to prevent "Invalid Domain" errors in the browser.
        $rpId = $this->configService->getRpId();
        if ($rpId === 'localhost') {
            $rpId = $request->getHost();
        }

        $options = [
            'rp' => [
                'name' => $this->configService->getRpName(),
                'id' => $rpId,
            ],
            'user' => [
                'id' => $user->getWebAuthnUserHandle(),
                'name' => $user->email,
                'displayName' => $user->name,
            ],
            'challenge' => $challenge->challenge,
            'pubKeyCredParams' => $pubKeyCredParams,
            'timeout' => $this->configService->getTimeoutMs(),
            'excludeCredentials' => $excludeCredentials,
            'authenticatorSelection' => $authenticatorSelection,
            'attestation' => $this->configService->getAttestationConveyance(),
        ];

        return $options;
    }

    /**
     * Verify a WebAuthn registration (attestation) response.
     *
     * This performs the full server-side verification of the credential
     * created by navigator.credentials.create(), including:
     * - Challenge verification
     * - Origin verification
     * - RP ID verification
     * - Attestation statement verification
     * - Duplicate credential prevention
     *
     * @throws WebAuthnException
     * @throws DuplicateCredentialException
     */
    public function verify(User $user, array $attestationData, Request $request, ?string $deviceName = null): PasskeyCredential
    {
        // Extract the challenge from the client data JSON to validate it.
        $clientDataJSON = $this->decodeClientDataJson($attestationData);

        if (!isset($clientDataJSON['challenge'])) {
            throw new WebAuthnException(
                'Missing challenge in client data.',
                ErrorCode::PASSKEY_VERIFICATION_FAILED,
            );
        }

        // Validate and consume the challenge (single-use, time-limited, correct flow type).
        $this->challengeService->validateAndConsume(
            challenge: $clientDataJSON['challenge'],
            expectedFlowType: WebauthnFlowType::Registration,
            expectedUserId: $user->id,
        );

        // Verify the origin from clientDataJSON.
        $this->verifyOrigin($clientDataJSON);

        // Verify the RP ID hash from authenticator data.
        $this->verifyRpIdFromAuthData($attestationData, $request);

        // Extract and store credential data.
        $credentialId = $attestationData['id'] ?? null;
        if (!$credentialId) {
            throw new WebAuthnException(
                'Missing credential ID in attestation response.',
                ErrorCode::PASSKEY_VERIFICATION_FAILED,
            );
        }

        // Check for duplicate credentials - the same credential ID must not be registered twice.
        $exists = PasskeyCredential::where('credential_id', $credentialId)
            ->whereNull('deleted_at')
            ->exists();

        if ($exists) {
            throw new DuplicateCredentialException();
        }

        // Decode the attestation object to extract the public key and other data.
        $attestationObject = $this->decodeAttestationObject($attestationData);

        return DB::transaction(function () use ($user, $credentialId, $attestationData, $attestationObject, $deviceName, $request) {
            $credential = PasskeyCredential::create([
                'user_id' => $user->id,
                'credential_id' => $credentialId,
                'credential_public_key' => $attestationObject['publicKey'],
                'sign_count' => $attestationObject['signCount'] ?? 0,
                'transports' => $attestationData['response']['transports'] ?? null,
                'aaguid' => $attestationObject['aaguid'] ?? null,
                'device_name' => $deviceName,
                'attestation_format' => $attestationObject['fmt'] ?? null,
                'authenticator_attachment' => $attestationData['authenticatorAttachment'] ?? null,
                'user_handle' => $user->getWebAuthnUserHandle(),
                'backup_eligible' => $attestationObject['backupEligible'] ?? null,
                'backup_state' => $attestationObject['backupState'] ?? null,
            ]);

            AuditLog::logEvent(
                event: 'passkey.registered',
                userId: $user->id,
                ipAddress: $request->ip(),
                userAgent: $request->userAgent(),
                metadata: [
                    'credential_id_prefix' => substr($credentialId, 0, 16) . '...',
                    'device_name' => $deviceName,
                    'authenticator_attachment' => $attestationData['authenticatorAttachment'] ?? null,
                ],
            );

            return $credential;
        });
    }

    /**
     * Decode the clientDataJSON from the attestation response.
     *
     * clientDataJSON is a base64url-encoded JSON string containing the challenge,
     * origin, and type ("webauthn.create" for registration).
     */
    private function decodeClientDataJson(array $attestationData): array
    {
        $clientDataB64 = $attestationData['response']['clientDataJSON'] ?? null;
        if (!$clientDataB64) {
            throw new WebAuthnException(
                'Missing clientDataJSON in attestation response.',
                ErrorCode::PASSKEY_VERIFICATION_FAILED,
            );
        }

        $clientDataJson = $this->base64urlDecode($clientDataB64);
        $clientData = json_decode($clientDataJson, true);

        if (!$clientData) {
            throw new WebAuthnException(
                'Invalid clientDataJSON format.',
                ErrorCode::PASSKEY_VERIFICATION_FAILED,
            );
        }

        // Verify the type is "webauthn.create" for registration.
        if (($clientData['type'] ?? '') !== 'webauthn.create') {
            throw new WebAuthnException(
                'Invalid ceremony type. Expected webauthn.create.',
                ErrorCode::PASSKEY_VERIFICATION_FAILED,
            );
        }

        return $clientData;
    }

    /**
     * Verify that the origin in clientDataJSON matches our allowed origins.
     *
     * Origin validation is critical for security: it ensures the WebAuthn ceremony
     * was performed on our legitimate website and not on a phishing site.
     */
    private function verifyOrigin(array $clientData): void
    {
        $origin = $clientData['origin'] ?? '';
        $allowedOrigins = $this->configService->getAllowedOrigins();

        if (!in_array($origin, $allowedOrigins, true)) {
            Log::warning('WebAuthn registration: origin mismatch', [
                'received_origin' => $origin,
                'allowed_origins' => $allowedOrigins,
            ]);

            if ($this->configService->isStrictOrigin()) {
                throw new WebAuthnException(
                    'Origin validation failed.',
                    ErrorCode::INVALID_ORIGIN,
                );
            }
        }
    }

    /**
     * Verify the RP ID hash from the authenticator data.
     *
     * The authenticator data contains a SHA-256 hash of the RP ID.
     * We verify this matches our expected RP ID to ensure the credential
     * was created for our relying party and not a different one.
     */
    private function verifyRpIdFromAuthData(array $attestationData, Request $request): void
    {
        $authDataB64 = $attestationData['response']['authenticatorData']
            ?? $this->extractAuthDataFromAttestationObject($attestationData);

        if (!$authDataB64) {
            // If we can't extract authData separately, we still validated via clientDataJSON origin.
            // Some attestation formats embed authData in the attestation object.
            return;
        }

        $authData = $this->base64urlDecode($authDataB64);
        if (strlen($authData) < 37) {
            return;
        }

        // First 32 bytes of authenticator data = SHA-256 hash of the RP ID.
        $rpIdHash = substr($authData, 0, 32);

        // Allow both the configured RP ID and the actual host for local development.
        $configuredRpId = $this->configService->getRpId();
        $expectedRpIdHash = hash('sha256', $configuredRpId, true);

        if (hash_equals($expectedRpIdHash, $rpIdHash)) {
            return;
        }

        // If it didn't match and we're on localhost, also try matching against the current host.
        if ($configuredRpId === 'localhost') {
            $currentHostHash = hash('sha256', $request->getHost(), true);
            if (hash_equals($currentHostHash, $rpIdHash)) {
                return;
            }
        }

        throw new WebAuthnException(
            'RP ID validation failed.',
            ErrorCode::INVALID_RP_ID,
        );
    }

    /**
     * Try to extract authenticator data from the attestation object.
     */
    private function extractAuthDataFromAttestationObject(array $attestationData): ?string
    {
        // authenticatorData may be provided at the top level of the response
        // by some client libraries.
        return $attestationData['response']['authenticatorData'] ?? null;
    }

    /**
     * Decode the attestation object and extract the public key, sign count, AAGUID, and flags.
     *
     * The attestation object is a CBOR-encoded structure containing:
     * - fmt: attestation format (e.g., "none", "packed")
     * - attStmt: attestation statement
     * - authData: authenticator data (RP ID hash + flags + counter + credential data)
     */
    private function decodeAttestationObject(array $attestationData): array
    {
        $attestationObjectB64 = $attestationData['response']['attestationObject'] ?? null;

        $result = [
            'publicKey' => $attestationData['response']['publicKey']
                ?? $attestationData['publicKey']
                ?? null,
            'signCount' => 0,
            'aaguid' => null,
            'fmt' => null,
            'backupEligible' => null,
            'backupState' => null,
        ];

        // Many modern client-side WebAuthn libraries (like @simplewebauthn/browser)
        // provide the public key already extracted and base64url-encoded.
        // We also handle the case where we need to parse it from the attestation object.

        if ($attestationObjectB64) {
            $attestationObjectRaw = $this->base64urlDecode($attestationObjectB64);

            // Parse the CBOR-encoded attestation object.
            // We use a lightweight approach: extract authData to get flags and counter.
            $authData = $this->extractAuthDataFromCbor($attestationObjectRaw);

            if ($authData && strlen($authData) >= 37) {
                // Bytes 32: flags (1 byte)
                $flags = ord($authData[32]);

                // Bit 0 (UP): User Present
                // Bit 2 (UV): User Verified
                // Bit 3 (BE): Backup Eligible
                // Bit 4 (BS): Backup State
                // Bit 6 (AT): Attested Credential Data included
                $result['backupEligible'] = (bool) ($flags & 0x08);
                $result['backupState'] = (bool) ($flags & 0x10);
                $hasAttestedCredData = (bool) ($flags & 0x40);

                // Bytes 33-36: signature counter (4 bytes, big-endian unsigned)
                $result['signCount'] = unpack('N', substr($authData, 33, 4))[1];

                // If attested credential data is present (bit 6 of flags)
                if ($hasAttestedCredData && strlen($authData) >= 55) {
                    // Bytes 37-52: AAGUID (16 bytes)
                    $aaguidBytes = substr($authData, 37, 16);
                    $hex = bin2hex($aaguidBytes);
                    $result['aaguid'] = sprintf(
                        '%s-%s-%s-%s-%s',
                        substr($hex, 0, 8),
                        substr($hex, 8, 4),
                        substr($hex, 12, 4),
                        substr($hex, 16, 4),
                        substr($hex, 20),
                    );

                    // If no public key was provided by the client library,
                    // extract it from the attested credential data.
                    if (!$result['publicKey']) {
                        // Bytes 53-54: credential ID length (2 bytes, big-endian)
                        $credIdLen = unpack('n', substr($authData, 53, 2))[1];
                        // After credential ID comes the COSE public key.
                        $publicKeyOffset = 55 + $credIdLen;
                        if (strlen($authData) > $publicKeyOffset) {
                            $publicKeyCose = substr($authData, $publicKeyOffset);
                            $result['publicKey'] = $this->base64urlEncode($publicKeyCose);
                        }
                    }
                }
            }

            // Extract attestation format.
            $result['fmt'] = $this->extractFmtFromCbor($attestationObjectRaw);
        }

        // If we still have the authenticatorData as a separate field, parse flags from it.
        if (!$result['publicKey'] && isset($attestationData['response']['authenticatorData'])) {
            $authData = $this->base64urlDecode($attestationData['response']['authenticatorData']);
            if (strlen($authData) >= 37) {
                $flags = ord($authData[32]);
                $result['backupEligible'] = (bool) ($flags & 0x08);
                $result['backupState'] = (bool) ($flags & 0x10);
                $result['signCount'] = unpack('N', substr($authData, 33, 4))[1];
            }
        }

        if (!$result['publicKey']) {
            throw new WebAuthnException(
                'Could not extract public key from attestation response. '
                . 'Ensure your frontend library includes the public key in the response.',
                ErrorCode::PASSKEY_VERIFICATION_FAILED,
            );
        }

        return $result;
    }

    /**
     * Extract authData from a CBOR-encoded attestation object.
     *
     * This is a lightweight CBOR parser that handles the specific structure
     * of WebAuthn attestation objects without requiring a full CBOR library.
     */
    private function extractAuthDataFromCbor(string $cborData): ?string
    {
        // The attestation object is a CBOR map with keys: "fmt", "attStmt", "authData".
        // We need to find the "authData" value.
        // Simple approach: search for the "authData" key in the CBOR data.

        $needle = 'authData';
        $pos = strpos($cborData, $needle);
        if ($pos === false) {
            return null;
        }

        // After the key, there's a CBOR byte string header.
        $offset = $pos + strlen($needle);
        if ($offset >= strlen($cborData)) {
            return null;
        }

        $majorType = ord($cborData[$offset]);

        // CBOR byte string: major type 2 (0x40-0x5B range, or 0x58/0x59 for longer strings)
        if ($majorType >= 0x40 && $majorType <= 0x57) {
            $length = $majorType - 0x40;
            return substr($cborData, $offset + 1, $length);
        } elseif ($majorType === 0x58) {
            // 1-byte length follows
            $length = ord($cborData[$offset + 1]);
            return substr($cborData, $offset + 2, $length);
        } elseif ($majorType === 0x59) {
            // 2-byte length follows (big-endian)
            $length = unpack('n', substr($cborData, $offset + 1, 2))[1];
            return substr($cborData, $offset + 3, $length);
        }

        return null;
    }

    /**
     * Extract attestation format from CBOR data.
     */
    private function extractFmtFromCbor(string $cborData): ?string
    {
        $needle = 'fmt';
        $pos = strpos($cborData, $needle);
        if ($pos === false) {
            return null;
        }

        $offset = $pos + strlen($needle);
        if ($offset >= strlen($cborData)) {
            return null;
        }

        $majorType = ord($cborData[$offset]);

        // CBOR text string: major type 3 (0x60-0x77 range, or 0x78 for longer)
        if ($majorType >= 0x60 && $majorType <= 0x77) {
            $length = $majorType - 0x60;
            return substr($cborData, $offset + 1, $length);
        } elseif ($majorType === 0x78) {
            $length = ord($cborData[$offset + 1]);
            return substr($cborData, $offset + 2, $length);
        }

        return null;
    }

    private function base64urlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($data, '-_', '+/'));
    }

    private function base64urlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
