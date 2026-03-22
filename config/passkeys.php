<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Passkey Feature Toggle
    |--------------------------------------------------------------------------
    |
    | Master switch to enable or disable the passkey authentication feature.
    | When disabled, all passkey endpoints will return a "not enabled" response.
    |
    */
    'enabled' => env('PASSKEY_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Relying Party (RP) Configuration
    |--------------------------------------------------------------------------
    |
    | The Relying Party represents your application in the WebAuthn protocol.
    |
    | rp_id: Your domain name (e.g., "example.com"). For local development,
    |        use "localhost". This MUST match the domain the user is on.
    |
    | rp_name: A human-readable name shown in browser/OS passkey prompts
    |          (e.g., "My Awesome App").
    |
    */
    'rp_id' => env('PASSKEY_RP_ID', 'localhost'),
    'rp_name' => env('PASSKEY_RP_NAME', 'Passkey Auth API'),

    /*
    |--------------------------------------------------------------------------
    | Allowed Origins
    |--------------------------------------------------------------------------
    |
    | Origins (protocol + domain + port) from which WebAuthn responses are
    | accepted. This is critical for security: the client origin in the
    | authenticator response is verified against this list.
    |
    | Provide as a comma-separated string in .env.
    |
    */
    'allowed_origins' => array_filter(
        array_map('trim', explode(',', env('PASSKEY_ALLOWED_ORIGINS', 'http://localhost:3000')))
    ),

    /*
    |--------------------------------------------------------------------------
    | Strict Origin Validation
    |--------------------------------------------------------------------------
    |
    | When true, origin validation is strictly enforced. Only set to false
    | during local development if you encounter origin mismatch issues.
    | MUST be true in production.
    |
    */
    'strict_origin' => env('PASSKEY_STRICT_ORIGIN', true),

    /*
    |--------------------------------------------------------------------------
    | Challenge Configuration
    |--------------------------------------------------------------------------
    |
    | challenge_ttl: How long (in seconds) a generated challenge remains valid.
    |                After this period, the challenge expires and cannot be used.
    |                Default: 300 seconds (5 minutes).
    |
    */
    'challenge_ttl' => (int) env('PASSKEY_CHALLENGE_TTL', 300),

    /*
    |--------------------------------------------------------------------------
    | Ceremony Timeout
    |--------------------------------------------------------------------------
    |
    | timeout_ms: The timeout (in milliseconds) passed to the browser for the
    |             WebAuthn ceremony. This is a hint to the browser/OS on how
    |             long to wait for the user to complete authentication.
    |             Default: 60000ms (60 seconds).
    |
    */
    'timeout_ms' => (int) env('PASSKEY_TIMEOUT_MS', 60000),

    /*
    |--------------------------------------------------------------------------
    | User Verification
    |--------------------------------------------------------------------------
    |
    | Controls whether the authenticator should verify the user's identity
    | (e.g., via biometric, PIN, or device passcode).
    |
    | "required"    - Always require user verification.
    | "preferred"   - Request verification if available, but allow without it.
    | "discouraged" - Do not request verification.
    |
    | IMPORTANT: The backend does NOT control HOW the user is verified.
    | The device/OS decides whether to use fingerprint, Face ID, Windows Hello
    | PIN, device passcode, etc. This is correct WebAuthn behavior.
    |
    */
    'user_verification' => env('PASSKEY_USER_VERIFICATION', 'preferred'),

    /*
    |--------------------------------------------------------------------------
    | Resident Key / Discoverable Credential
    |--------------------------------------------------------------------------
    |
    | Controls whether the credential should be stored as a discoverable
    | (resident) credential on the authenticator.
    |
    | "required"    - Credential MUST be discoverable (enables username-less login).
    | "preferred"   - Request discoverable if supported.
    | "discouraged" - Do not request discoverable credential.
    |
    */
    'resident_key' => env('PASSKEY_RESIDENT_KEY', 'required'),

    /*
    |--------------------------------------------------------------------------
    | Attestation Conveyance
    |--------------------------------------------------------------------------
    |
    | Controls whether the authenticator should provide an attestation
    | statement during registration.
    |
    | "none"     - No attestation needed (recommended for most apps).
    | "indirect" - Attestation may be anonymized.
    | "direct"   - Full attestation from the authenticator.
    |
    */
    'attestation' => env('PASSKEY_ATTESTATION', 'none'),

    /*
    |--------------------------------------------------------------------------
    | Authenticator Attachment
    |--------------------------------------------------------------------------
    |
    | Restricts which type of authenticator can be used.
    |
    | "platform"      - Only built-in authenticators (Touch ID, Windows Hello, etc.)
    | "cross-platform" - Only roaming authenticators (USB security keys, etc.)
    | null             - No preference (allows both).
    |
    */
    'authenticator_attachment' => env('PASSKEY_AUTHENTICATOR_ATTACHMENT') ?: null,

    /*
    |--------------------------------------------------------------------------
    | Audit Logging
    |--------------------------------------------------------------------------
    |
    | When enabled, security-relevant WebAuthn events (registrations, logins,
    | failures) are logged to the audit_logs table. Sensitive data like private
    | keys is NEVER logged.
    |
    */
    'audit_log' => env('PASSKEY_AUDIT_LOG', true),

];
