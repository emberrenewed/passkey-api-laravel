<?php

namespace App\Services\Auth\Passkey;

use App\Enums\ErrorCode;
use App\Enums\WebauthnFlowType;
use App\Exceptions\CredentialNotFoundException;
use App\Exceptions\WebAuthnException;
use App\Models\AuditLog;
use App\Models\PasskeyCredential;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

/**
 * Handles the WebAuthn authentication ceremony (logging in with an existing passkey).
 *
 * Authentication flow:
 * 1. Generate authentication options (challenge + optionally allowed credential IDs)
 * 2. Client calls navigator.credentials.get() with these options
 * 3. Client sends the assertion response back to verify
 * 4. Server verifies the assertion signature, challenge, origin, RP ID, and sign count
 * 5. Server issues a Sanctum token upon success
 *
 * IMPORTANT: This service supports two login strategies:
 * A) Email-first: The user provides their email, and we return their registered credential IDs
 *    in the allowCredentials list. The browser only prompts for matching credentials.
 * B) Discoverable (username-less): No email is provided; the authenticator uses a
 *    discoverable/resident credential. The user is identified by the userHandle in the response.
 *
 * Both strategies are supported simultaneously.
 *
 * SECURITY NOTE: The backend does NOT control what user verification method is used.
 * Whether the user authenticates with fingerprint, Face ID, Windows Hello PIN,
 * or device passcode is entirely decided by the device/OS. The backend only specifies
 * the userVerification preference ("required"/"preferred"/"discouraged"), and the
 * platform authenticator decides HOW to verify. This is correct WebAuthn behavior.
 * Do NOT build a custom PIN system - the OS handles this securely.
 */
class PasskeyAuthenticationService
{
    public function __construct(
        private WebAuthnConfigService $configService,
        private ChallengeService $challengeService,
        private TokenService $tokenService,
    ) {}

    /**
     * Generate WebAuthn authentication options.
     *
     * @param string|null $email If provided, returns allowCredentials for this user (email-first flow).
     *                           If null, enables discoverable credential flow (username-less login).
     */
    public function generateOptions(?string $email, Request $request): array
    {
        $userId = null;
        $allowCredentials = [];

        if ($email) {
            // Email-first flow: find the user and their registered credentials.
            $user = User::where('email', $email)->first();

            if ($user) {
                $userId = $user->id;

                // List the user's credentials so the browser knows which authenticators to prompt.
                $allowCredentials = $user->activePasskeyCredentials
                    ->map(fn (PasskeyCredential $cred) => [
                        'type' => 'public-key',
                        'id' => $cred->credential_id,
                        'transports' => $cred->transports ?? [],
                    ])
                    ->values()
                    ->toArray();
            }

            // If user not found, we still generate options with an empty allowCredentials
            // to avoid leaking whether the email exists (timing attack mitigation).
        }

        $challenge = $this->challengeService->create(
            flowType: WebauthnFlowType::Authentication,
            userId: $userId,
            context: [
                'ip' => $request->ip(),
                'user_agent' => $request->userAgent(),
                'email' => $email,
            ],
        );

        $options = [
            'challenge' => $challenge->challenge,
            'timeout' => $this->configService->getTimeoutMs(),
            'rpId' => $this->configService->getRpId(),
            'userVerification' => $this->configService->getUserVerification(),
        ];

        // Only include allowCredentials for email-first flow.
        // For discoverable flow, omitting allowCredentials tells the browser
        // to use a resident/discoverable credential.
        if (!empty($allowCredentials)) {
            $options['allowCredentials'] = $allowCredentials;
        }

        return $options;
    }

    /**
     * Verify a WebAuthn authentication (assertion) response and issue a token.
     *
     * Performs the full server-side assertion verification:
     * 1. Decode and validate clientDataJSON (challenge, origin, type)
     * 2. Find the credential in the database
     * 3. Verify the RP ID hash from authenticator data
     * 4. Verify the signature using the stored public key
     * 5. Verify and update the signature counter
     * 6. Issue a Sanctum API token
     *
     * @return array{token: string, token_type: string, user: User}
     * @throws WebAuthnException
     */
    public function verify(array $assertionData, Request $request): array
    {
        // Step 1: Decode clientDataJSON and verify challenge.
        $clientDataJSON = $this->decodeClientDataJson($assertionData);

        if (!isset($clientDataJSON['challenge'])) {
            throw new WebAuthnException(
                'Missing challenge in client data.',
                ErrorCode::PASSKEY_VERIFICATION_FAILED,
            );
        }

        // For discoverable credential flow, the challenge may not be bound to a specific user.
        $challengeRecord = $this->challengeService->validateAndConsume(
            challenge: $clientDataJSON['challenge'],
            expectedFlowType: WebauthnFlowType::Authentication,
        );

        // Step 2: Verify origin.
        $this->verifyOrigin($clientDataJSON);

        // Step 3: Find the credential.
        $credentialId = $assertionData['id'] ?? null;
        if (!$credentialId) {
            throw new WebAuthnException(
                'Missing credential ID in assertion response.',
                ErrorCode::PASSKEY_VERIFICATION_FAILED,
            );
        }

        $credential = PasskeyCredential::where('credential_id', $credentialId)
            ->whereNull('deleted_at')
            ->first();

        if (!$credential) {
            AuditLog::logEvent(
                event: 'passkey.login.credential_not_found',
                ipAddress: $request->ip(),
                userAgent: $request->userAgent(),
                metadata: ['credential_id_prefix' => substr($credentialId, 0, 16) . '...'],
            );

            throw new CredentialNotFoundException('Credential not found or has been revoked.');
        }

        $user = $credential->user;

        // If the challenge was bound to a specific user, verify it matches.
        if ($challengeRecord->user_id !== null && $challengeRecord->user_id !== $user->id) {
            throw new WebAuthnException(
                'Credential does not match the expected user.',
                ErrorCode::PASSKEY_VERIFICATION_FAILED,
            );
        }

        // Step 4: Verify RP ID hash from authenticator data.
        $this->verifyRpIdFromAuthData($assertionData);

        // Step 5: Verify user flags (User Present, User Verified).
        $this->verifyUserFlags($assertionData);

        // Step 6: Verify the assertion signature.
        $this->verifySignature($assertionData, $credential);

        // Step 7: Verify and update the signature counter.
        $this->verifyAndUpdateSignCount($assertionData, $credential, $request);

        // Step 8: Update last_used_at.
        $credential->markAsUsed();

        // Step 9: Issue Sanctum token.
        $token = $this->tokenService->createToken($user, 'passkey-auth');

        AuditLog::logEvent(
            event: 'passkey.login.success',
            userId: $user->id,
            ipAddress: $request->ip(),
            userAgent: $request->userAgent(),
            metadata: [
                'credential_id_prefix' => substr($credentialId, 0, 16) . '...',
                'device_name' => $credential->device_name,
            ],
        );

        return [
            'token' => $token,
            'token_type' => 'Bearer',
            'user' => $user,
        ];
    }

    /**
     * Decode clientDataJSON and verify the ceremony type.
     */
    private function decodeClientDataJson(array $assertionData): array
    {
        $clientDataB64 = $assertionData['response']['clientDataJSON'] ?? null;
        if (!$clientDataB64) {
            throw new WebAuthnException(
                'Missing clientDataJSON in assertion response.',
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

        // Verify the type is "webauthn.get" for authentication.
        if (($clientData['type'] ?? '') !== 'webauthn.get') {
            throw new WebAuthnException(
                'Invalid ceremony type. Expected webauthn.get.',
                ErrorCode::PASSKEY_VERIFICATION_FAILED,
            );
        }

        return $clientData;
    }

    /**
     * Verify origin from clientDataJSON.
     */
    private function verifyOrigin(array $clientData): void
    {
        $origin = $clientData['origin'] ?? '';
        $allowedOrigins = $this->configService->getAllowedOrigins();

        if (!in_array($origin, $allowedOrigins, true)) {
            Log::warning('WebAuthn authentication: origin mismatch', [
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
     * Verify RP ID hash from authenticator data.
     */
    private function verifyRpIdFromAuthData(array $assertionData): void
    {
        $authDataB64 = $assertionData['response']['authenticatorData'] ?? null;
        if (!$authDataB64) {
            return;
        }

        $authData = $this->base64urlDecode($authDataB64);
        if (strlen($authData) < 37) {
            throw new WebAuthnException(
                'Authenticator data is too short.',
                ErrorCode::PASSKEY_VERIFICATION_FAILED,
            );
        }

        // First 32 bytes = SHA-256(RP ID)
        $rpIdHash = substr($authData, 0, 32);
        $expectedRpIdHash = hash('sha256', $this->configService->getRpId(), true);

        if (!hash_equals($expectedRpIdHash, $rpIdHash)) {
            throw new WebAuthnException(
                'RP ID validation failed. The credential was not created for this relying party.',
                ErrorCode::INVALID_RP_ID,
            );
        }
    }

    /**
     * Verify user presence and verification flags in authenticator data.
     */
    private function verifyUserFlags(array $assertionData): void
    {
        $authDataB64 = $assertionData['response']['authenticatorData'] ?? null;
        if (!$authDataB64) {
            return;
        }

        $authData = $this->base64urlDecode($authDataB64);
        if (strlen($authData) < 33) {
            return;
        }

        $flags = ord($authData[32]);

        // Bit 0 (UP): User Present flag MUST be set.
        if (!($flags & 0x01)) {
            throw new WebAuthnException(
                'User presence flag not set in authenticator data.',
                ErrorCode::PASSKEY_VERIFICATION_FAILED,
            );
        }

        // Bit 2 (UV): User Verified - check based on our policy.
        $uvRequired = $this->configService->getUserVerification() === 'required';
        if ($uvRequired && !($flags & 0x04)) {
            throw new WebAuthnException(
                'User verification is required but was not performed by the authenticator.',
                ErrorCode::PASSKEY_VERIFICATION_FAILED,
            );
        }
    }

    /**
     * Verify the assertion signature using the stored public key.
     *
     * The authenticator signs (authenticatorData || SHA-256(clientDataJSON))
     * with the credential's private key. We verify this signature using
     * the stored public key.
     */
    private function verifySignature(array $assertionData, PasskeyCredential $credential): void
    {
        $authDataB64 = $assertionData['response']['authenticatorData'] ?? null;
        $clientDataB64 = $assertionData['response']['clientDataJSON'] ?? null;
        $signatureB64 = $assertionData['response']['signature'] ?? null;

        if (!$authDataB64 || !$clientDataB64 || !$signatureB64) {
            throw new WebAuthnException(
                'Missing required fields in assertion response (authenticatorData, clientDataJSON, signature).',
                ErrorCode::PASSKEY_VERIFICATION_FAILED,
            );
        }

        $authenticatorData = $this->base64urlDecode($authDataB64);
        $clientDataJSON = $this->base64urlDecode($clientDataB64);
        $signature = $this->base64urlDecode($signatureB64);

        // The signed data is: authenticatorData || SHA-256(clientDataJSON)
        $clientDataHash = hash('sha256', $clientDataJSON, true);
        $signedData = $authenticatorData . $clientDataHash;

        // Decode the stored public key (base64url-encoded).
        // The key may be in SPKI/DER format (from getPublicKey()) or COSE format
        // (extracted from the attestation object). We detect the format and handle both.
        $publicKeyRaw = $this->base64urlDecode($credential->credential_public_key);

        $publicKeyPem = null;
        $algorithm = -7; // Default ES256

        // Check if it's SPKI/DER format (starts with ASN.1 SEQUENCE tag 0x30).
        // getPublicKey() from the WebAuthn API returns SPKI DER, not COSE.
        if (strlen($publicKeyRaw) > 0 && ord($publicKeyRaw[0]) === 0x30) {
            // Already in SPKI DER format - just wrap in PEM headers.
            $publicKeyPem = "-----BEGIN PUBLIC KEY-----\n"
                . chunk_split(base64_encode($publicKeyRaw), 64, "\n")
                . "-----END PUBLIC KEY-----\n";

            // Detect algorithm from the SPKI structure.
            $algorithm = $this->detectAlgorithmFromSpki($publicKeyRaw);
        } else {
            // COSE format - decode via CBOR.
            $publicKeyPem = $this->coseKeyToPem($publicKeyRaw);
            $algorithm = $this->getCoseAlgorithm($publicKeyRaw);
        }

        if (!$publicKeyPem) {
            throw new WebAuthnException(
                'Failed to process the stored public key.',
                ErrorCode::PASSKEY_VERIFICATION_FAILED,
            );
        }

        $opensslAlgo = match ($algorithm) {
            -7 => OPENSSL_ALGO_SHA256,     // ES256
            -257 => OPENSSL_ALGO_SHA256,   // RS256
            -8 => null,                     // EdDSA - handled separately
            default => OPENSSL_ALGO_SHA256,
        };

        if ($algorithm === -8) {
            $verified = $this->verifyEdDSA($signedData, $signature, $publicKeyRaw);
        } else {
            $pkey = openssl_pkey_get_public($publicKeyPem);
            if (!$pkey) {
                throw new WebAuthnException(
                    'Invalid public key.',
                    ErrorCode::PASSKEY_VERIFICATION_FAILED,
                );
            }

            $verified = openssl_verify($signedData, $signature, $pkey, $opensslAlgo);
        }

        if ($verified !== 1 && $verified !== true) {
            AuditLog::logEvent(
                event: 'passkey.login.signature_invalid',
                userId: $credential->user_id,
                metadata: ['credential_id_prefix' => substr($credential->credential_id, 0, 16) . '...'],
            );

            throw new WebAuthnException(
                'Signature verification failed. The assertion signature is invalid.',
                ErrorCode::PASSKEY_VERIFICATION_FAILED,
            );
        }
    }

    /**
     * Verify and update the signature counter.
     *
     * The signature counter is a security feature that helps detect cloned authenticators.
     * Each time a credential is used, the authenticator increments its counter.
     * If the server sees a counter value less than or equal to the stored value,
     * it may indicate the credential has been cloned.
     *
     * Note: Some authenticators (especially synced passkeys) may always report 0.
     * We handle this gracefully: if both stored and new counts are 0, we allow it.
     */
    private function verifyAndUpdateSignCount(
        array $assertionData,
        PasskeyCredential $credential,
        Request $request,
    ): void {
        $authDataB64 = $assertionData['response']['authenticatorData'] ?? null;
        if (!$authDataB64) {
            return;
        }

        $authData = $this->base64urlDecode($authDataB64);
        if (strlen($authData) < 37) {
            return;
        }

        // Bytes 33-36: signature counter (4 bytes, big-endian unsigned)
        $newSignCount = unpack('N', substr($authData, 33, 4))[1];
        $storedSignCount = $credential->sign_count;

        // If both are 0, the authenticator doesn't support counters (common with synced passkeys).
        // Allow this case.
        if ($storedSignCount === 0 && $newSignCount === 0) {
            return;
        }

        // The new count must be strictly greater than the stored count.
        if ($newSignCount <= $storedSignCount) {
            AuditLog::logEvent(
                event: 'passkey.login.sign_count_mismatch',
                userId: $credential->user_id,
                ipAddress: $request->ip(),
                userAgent: $request->userAgent(),
                metadata: [
                    'stored_count' => $storedSignCount,
                    'received_count' => $newSignCount,
                    'credential_id_prefix' => substr($credential->credential_id, 0, 16) . '...',
                ],
            );

            Log::warning('WebAuthn sign count regression detected - possible cloned authenticator', [
                'user_id' => $credential->user_id,
                'stored' => $storedSignCount,
                'received' => $newSignCount,
            ]);

            throw new WebAuthnException(
                'Signature counter validation failed. This may indicate a cloned authenticator.',
                ErrorCode::SIGN_COUNT_MISMATCH,
            );
        }

        $credential->updateSignCount($newSignCount);
    }

    /**
     * Detect the algorithm from an SPKI DER public key structure.
     * Looks at the OID in the AlgorithmIdentifier to determine EC vs RSA.
     */
    private function detectAlgorithmFromSpki(string $der): int
    {
        // EC P-256 OID: 1.2.840.10045.3.1.7 (hex: 2a 86 48 ce 3d 03 01 07)
        if (str_contains($der, "\x2a\x86\x48\xce\x3d\x03\x01\x07")) {
            return -7; // ES256
        }

        // RSA OID: 1.2.840.113549.1.1.1 (hex: 2a 86 48 86 f7 0d 01 01 01)
        if (str_contains($der, "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01")) {
            return -257; // RS256
        }

        // Ed25519 OID: 1.3.101.112 (hex: 06 03 2b 65 70)
        if (str_contains($der, "\x2b\x65\x70")) {
            return -8; // EdDSA
        }

        return -7; // Default ES256
    }

    /**
     * Convert a COSE-encoded public key to PEM format for OpenSSL verification.
     *
     * Supports:
     * - ES256 (ECDSA with P-256 / COSE algorithm -7)
     * - RS256 (RSASSA-PKCS1-v1_5 / COSE algorithm -257)
     */
    private function coseKeyToPem(string $coseKey): ?string
    {
        $cborData = $this->decodeCborMap($coseKey);
        if (!$cborData) {
            return null;
        }

        // COSE key type (kty): 1 = integer key type
        // 2 = EC2 (Elliptic Curve), 3 = RSA
        $kty = $cborData[1] ?? null; // Key type
        $alg = $cborData[3] ?? null; // Algorithm

        if ($kty === 2) {
            // EC2 key (ES256)
            return $this->ec2KeyToPem($cborData);
        } elseif ($kty === 3) {
            // RSA key (RS256)
            return $this->rsaKeyToPem($cborData);
        }

        return null;
    }

    /**
     * Get the COSE algorithm identifier from a COSE key.
     */
    private function getCoseAlgorithm(string $coseKey): int
    {
        $cborData = $this->decodeCborMap($coseKey);
        return $cborData[3] ?? -7; // Default to ES256
    }

    /**
     * Convert an EC2 COSE key to PEM format.
     */
    private function ec2KeyToPem(array $cborData): ?string
    {
        // -2 = x-coordinate, -3 = y-coordinate (both 32 bytes for P-256)
        $x = $cborData[-2] ?? null;
        $y = $cborData[-3] ?? null;

        if (!$x || !$y) {
            return null;
        }

        // Construct the uncompressed EC point: 0x04 || x || y
        $publicKeyPoint = "\x04" . $x . $y;

        // Wrap in SubjectPublicKeyInfo ASN.1 structure for P-256.
        // OID for id-ecPublicKey: 1.2.840.10045.2.1
        // OID for prime256v1 (P-256): 1.2.840.10045.3.1.7
        $asn1 = "\x30" . chr(strlen($publicKeyPoint) + 24)
            . "\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"
            . "\x03" . chr(strlen($publicKeyPoint) + 1) . "\x00" . $publicKeyPoint;

        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($asn1), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    /**
     * Convert an RSA COSE key to PEM format.
     */
    private function rsaKeyToPem(array $cborData): ?string
    {
        // -1 = n (modulus), -2 = e (exponent)
        $n = $cborData[-1] ?? null;
        $e = $cborData[-2] ?? null;

        if (!$n || !$e) {
            return null;
        }

        // Build ASN.1 RSAPublicKey structure.
        $modulus = $this->asn1Integer($n);
        $exponent = $this->asn1Integer($e);

        $rsaPublicKey = "\x30" . $this->asn1Length(strlen($modulus) + strlen($exponent))
            . $modulus . $exponent;

        // Wrap in SubjectPublicKeyInfo.
        // OID for rsaEncryption: 1.2.840.113549.1.1.1
        $algorithmIdentifier = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
        $bitString = "\x03" . $this->asn1Length(strlen($rsaPublicKey) + 1) . "\x00" . $rsaPublicKey;
        $spki = "\x30" . $this->asn1Length(strlen($algorithmIdentifier) + strlen($bitString))
            . $algorithmIdentifier . $bitString;

        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($spki), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    private function asn1Integer(string $bytes): string
    {
        // Ensure positive integer (prepend 0x00 if high bit is set).
        if (ord($bytes[0]) & 0x80) {
            $bytes = "\x00" . $bytes;
        }
        return "\x02" . $this->asn1Length(strlen($bytes)) . $bytes;
    }

    private function asn1Length(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        } elseif ($length < 0x100) {
            return "\x81" . chr($length);
        } else {
            return "\x82" . pack('n', $length);
        }
    }

    /**
     * Decode a CBOR map (simplified decoder for COSE keys).
     *
     * This handles the specific CBOR structures used in WebAuthn COSE keys.
     * Supports integer and negative integer keys, byte strings, and integer values.
     */
    private function decodeCborMap(string $data): ?array
    {
        if (strlen($data) < 1) {
            return null;
        }

        $offset = 0;
        $result = [];

        $firstByte = ord($data[$offset]);
        $majorType = ($firstByte & 0xe0) >> 5;

        // Must be a map (major type 5).
        if ($majorType !== 5) {
            return null;
        }

        $mapSize = $firstByte & 0x1f;
        if ($mapSize === 24) {
            $mapSize = ord($data[++$offset]);
        }
        $offset++;

        for ($i = 0; $i < $mapSize && $offset < strlen($data); $i++) {
            // Decode key.
            $key = $this->decodeCborValue($data, $offset);
            if ($key === null) {
                break;
            }

            // Decode value.
            $value = $this->decodeCborValue($data, $offset);
            if ($value === null) {
                break;
            }

            $result[$key] = $value;
        }

        return $result;
    }

    /**
     * Decode a single CBOR value and advance the offset.
     */
    private function decodeCborValue(string $data, int &$offset): mixed
    {
        if ($offset >= strlen($data)) {
            return null;
        }

        $byte = ord($data[$offset]);
        $majorType = ($byte & 0xe0) >> 5;
        $additionalInfo = $byte & 0x1f;
        $offset++;

        return match ($majorType) {
            0 => $this->decodeCborUnsigned($additionalInfo, $data, $offset),        // Unsigned integer
            1 => -1 - $this->decodeCborUnsigned($additionalInfo, $data, $offset),  // Negative integer
            2 => $this->decodeCborByteString($additionalInfo, $data, $offset),      // Byte string
            3 => $this->decodeCborTextString($additionalInfo, $data, $offset),      // Text string
            4 => $this->decodeCborArray($additionalInfo, $data, $offset),           // Array
            5 => $this->decodeCborNestedMap($additionalInfo, $data, $offset),       // Map
            6 => $this->decodeCborValue($data, $offset),                            // Tag (skip tag, decode content)
            7 => $this->decodeCborSimple($additionalInfo),                          // Simple/float
            default => null,
        };
    }

    private function decodeCborUnsigned(int $info, string $data, int &$offset): int
    {
        if ($info < 24) {
            return $info;
        } elseif ($info === 24) {
            return ord($data[$offset++]);
        } elseif ($info === 25) {
            $val = unpack('n', substr($data, $offset, 2))[1];
            $offset += 2;
            return $val;
        } elseif ($info === 26) {
            $val = unpack('N', substr($data, $offset, 4))[1];
            $offset += 4;
            return $val;
        }
        return 0;
    }

    private function decodeCborByteString(int $info, string $data, int &$offset): string
    {
        $length = $this->decodeCborUnsigned($info, $data, $offset);
        $value = substr($data, $offset, $length);
        $offset += $length;
        return $value;
    }

    private function decodeCborTextString(int $info, string $data, int &$offset): string
    {
        return $this->decodeCborByteString($info, $data, $offset);
    }

    private function decodeCborArray(int $info, string $data, int &$offset): array
    {
        $count = $this->decodeCborUnsigned($info, $data, $offset);
        $result = [];
        for ($i = 0; $i < $count && $offset < strlen($data); $i++) {
            $result[] = $this->decodeCborValue($data, $offset);
        }
        return $result;
    }

    private function decodeCborNestedMap(int $info, string $data, int &$offset): array
    {
        $count = $this->decodeCborUnsigned($info, $data, $offset);
        $result = [];
        for ($i = 0; $i < $count && $offset < strlen($data); $i++) {
            $key = $this->decodeCborValue($data, $offset);
            $value = $this->decodeCborValue($data, $offset);
            $result[$key] = $value;
        }
        return $result;
    }

    private function decodeCborSimple(int $info): mixed
    {
        return match ($info) {
            20 => false,
            21 => true,
            22 => null,
            default => null,
        };
    }

    /**
     * Verify an EdDSA (Ed25519) signature using sodium.
     */
    private function verifyEdDSA(string $data, string $signature, string $coseKey): bool
    {
        if (!function_exists('sodium_crypto_sign_verify_detached')) {
            throw new WebAuthnException(
                'EdDSA verification requires the sodium extension.',
                ErrorCode::PASSKEY_VERIFICATION_FAILED,
            );
        }

        $cborData = $this->decodeCborMap($coseKey);
        $publicKey = $cborData[-2] ?? null; // x-coordinate for Ed25519

        if (!$publicKey || strlen($publicKey) !== 32) {
            return false;
        }

        try {
            return sodium_crypto_sign_verify_detached($signature, $data, $publicKey);
        } catch (\SodiumException) {
            return false;
        }
    }

    private function base64urlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($data, '-_', '+/'));
    }
}
