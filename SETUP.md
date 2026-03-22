# Passkey Authentication API - Setup & Documentation

## Table of Contents

1. [Overview](#overview)
2. [Requirements](#requirements)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Database Setup](#database-setup)
6. [API Endpoints](#api-endpoints)
7. [Request & Response Examples](#request--response-examples)
8. [Frontend Integration Guide](#frontend-integration-guide)
9. [Authentication Flows](#authentication-flows)
10. [Security Architecture](#security-architecture)
11. [Testing Guide](#testing-guide)
12. [Production Deployment](#production-deployment)
13. [Troubleshooting](#troubleshooting)

---

## Overview

A production-ready REST API for **Passkey (WebAuthn/FIDO2) authentication** built with Laravel. This API provides real WebAuthn credential registration and authentication, NOT a custom PIN system.

### Key Principles

- **Real WebAuthn**: Uses the WebAuthn standard for credential creation and assertion verification
- **No Custom PIN**: The backend does NOT implement its own PIN system. When biometrics are unavailable, the **device/OS handles secure unlock** (Windows Hello PIN, Android device PIN, iPhone passcode, etc.)
- **Server-Side Verification**: Challenges, origins, RP IDs, signatures, and sign counts are all verified server-side
- **Token-Based Auth**: After successful passkey authentication, a Laravel Sanctum API token is issued

---

## Requirements

- PHP >= 8.2
- MySQL >= 8.0 (or MariaDB >= 10.6)
- Composer >= 2.0
- OpenSSL PHP extension
- Sodium PHP extension (for EdDSA/Ed25519 support)
- Laravel 11.x

---

## Installation

### Step 1: Clone & Install Dependencies

```bash
cd "passkey api laravel"
composer install
```

### Step 2: Environment Configuration

```bash
cp .env.example .env
php artisan key:generate
```

### Step 3: Configure Database

Edit `.env` with your MySQL credentials:

```env
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=passkey_auth
DB_USERNAME=root
DB_PASSWORD=your_password
```

### Step 4: Create Database

```sql
CREATE DATABASE passkey_auth CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### Step 5: Run Migrations

```bash
php artisan migrate
```

### Step 6: Configure Passkey Settings

Edit `.env` with your domain settings:

```env
# For local development
PASSKEY_RP_ID=localhost
PASSKEY_RP_NAME="My App"
PASSKEY_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173

# For production
PASSKEY_RP_ID=example.com
PASSKEY_RP_NAME="My App"
PASSKEY_ALLOWED_ORIGINS=https://example.com
```

### Step 7: Start the Server

```bash
php artisan serve
```

### Step 8: Schedule Challenge Cleanup

Add to your server's crontab:

```bash
* * * * * cd /path-to-project && php artisan schedule:run >> /dev/null 2>&1
```

Or run manually:

```bash
php artisan passkey:purge-challenges
```

---

## Configuration

### config/passkeys.php

| Key | Env Variable | Default | Description |
|-----|-------------|---------|-------------|
| `enabled` | `PASSKEY_ENABLED` | `true` | Master switch for passkey feature |
| `rp_id` | `PASSKEY_RP_ID` | `localhost` | Relying Party ID (your domain) |
| `rp_name` | `PASSKEY_RP_NAME` | `Passkey Auth API` | Human-readable RP name |
| `allowed_origins` | `PASSKEY_ALLOWED_ORIGINS` | `http://localhost:3000` | Comma-separated allowed origins |
| `strict_origin` | `PASSKEY_STRICT_ORIGIN` | `true` | Enforce strict origin validation |
| `challenge_ttl` | `PASSKEY_CHALLENGE_TTL` | `300` | Challenge validity in seconds |
| `timeout_ms` | `PASSKEY_TIMEOUT_MS` | `60000` | Browser ceremony timeout in ms |
| `user_verification` | `PASSKEY_USER_VERIFICATION` | `preferred` | User verification preference |
| `resident_key` | `PASSKEY_RESIDENT_KEY` | `required` | Discoverable credential requirement |
| `attestation` | `PASSKEY_ATTESTATION` | `none` | Attestation conveyance preference |
| `authenticator_attachment` | `PASSKEY_AUTHENTICATOR_ATTACHMENT` | `null` | Authenticator type preference |
| `audit_log` | `PASSKEY_AUDIT_LOG` | `true` | Enable security audit logging |

### User Verification Explained

The `user_verification` setting tells the authenticator WHETHER to verify the user, not HOW. The actual method is decided by the device:

| Device | Possible Methods |
|--------|-----------------|
| Windows | Windows Hello (face, fingerprint, or PIN) |
| Android | Fingerprint, face unlock, device PIN/pattern |
| iPhone/iPad | Face ID, Touch ID, or device passcode |
| macOS | Touch ID or login password |

**The backend does NOT control which method is used. This is correct WebAuthn behavior.**

---

## Database Setup

### Tables Created

1. **users** - User accounts (password is nullable for passkey-only accounts)
2. **passkey_credentials** - Stored WebAuthn credentials (public keys, sign counts, metadata)
3. **webauthn_challenges** - Time-limited, single-use challenges for replay protection
4. **audit_logs** - Security event logging (never stores sensitive data)
5. **personal_access_tokens** - Sanctum API tokens
6. **password_reset_tokens** - Optional password reset support
7. **cache** / **cache_locks** - Application cache

---

## API Endpoints

### Public Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/register` | Create user account |
| `GET` | `/api/auth/passkey/support-check` | Get backend passkey config |
| `POST` | `/api/auth/passkey/register/options` | Generate passkey registration options |
| `POST` | `/api/auth/passkey/register/verify` | Verify passkey registration |
| `POST` | `/api/auth/passkey/login/options` | Generate passkey login options |
| `POST` | `/api/auth/passkey/login/verify` | Verify passkey login & get token |
| `POST` | `/api/auth/login/password` | Backup password login |

### Authenticated Endpoints (Bearer token required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/auth/me` | Get current user profile |
| `POST` | `/api/auth/logout` | Revoke current token |
| `GET` | `/api/auth/passkeys` | List user's passkeys |
| `PATCH` | `/api/auth/passkeys/{id}` | Rename a passkey |
| `DELETE` | `/api/auth/passkeys/{id}` | Delete a passkey |
| `POST` | `/api/auth/passkeys/add/options` | Generate options for additional passkey |
| `POST` | `/api/auth/passkeys/add/verify` | Verify additional passkey registration |

---

## Request & Response Examples

### 1. Register Account

**Request:**
```http
POST /api/auth/register
Content-Type: application/json

{
  "name": "Adam",
  "email": "adam@example.com",
  "password": "optional_backup_password",
  "password_confirmation": "optional_backup_password"
}
```

**Response (201):**
```json
{
  "success": true,
  "message": "Account created successfully. Please register a passkey to secure your account.",
  "data": {
    "user": {
      "id": 1,
      "name": "Adam",
      "email": "adam@example.com",
      "email_verified_at": null,
      "has_passkey": false,
      "has_password": true,
      "passkey_count": 0,
      "created_at": "2024-01-15T10:30:00+00:00",
      "updated_at": "2024-01-15T10:30:00+00:00"
    }
  }
}
```

### 2. Passkey Registration Options

**Request:**
```http
POST /api/auth/passkey/register/options
Content-Type: application/json

{
  "user_id": 1
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Passkey registration options generated.",
  "data": {
    "publicKey": {
      "rp": {
        "name": "Passkey Auth API",
        "id": "localhost"
      },
      "user": {
        "id": "1",
        "name": "adam@example.com",
        "displayName": "Adam"
      },
      "challenge": "dGhpcyBpcyBhIHJhbmRvbSBjaGFsbGVuZ2U",
      "pubKeyCredParams": [
        { "type": "public-key", "alg": -7 },
        { "type": "public-key", "alg": -257 },
        { "type": "public-key", "alg": -8 }
      ],
      "timeout": 60000,
      "excludeCredentials": [],
      "authenticatorSelection": {
        "userVerification": "preferred",
        "residentKey": "required",
        "requireResidentKey": true
      },
      "attestation": "none"
    }
  }
}
```

### 3. Passkey Registration Verify

**Request:**
```http
POST /api/auth/passkey/register/verify
Content-Type: application/json

{
  "user_id": 1,
  "id": "credential-id-base64url",
  "rawId": "credential-id-base64url",
  "type": "public-key",
  "response": {
    "clientDataJSON": "base64url-encoded-client-data",
    "attestationObject": "base64url-encoded-attestation",
    "transports": ["internal", "hybrid"],
    "publicKey": "base64url-encoded-public-key",
    "authenticatorData": "base64url-encoded-auth-data"
  },
  "authenticatorAttachment": "platform",
  "device_name": "Adam's Windows Laptop"
}
```

**Response (201):**
```json
{
  "success": true,
  "message": "Passkey registered successfully.",
  "data": {
    "passkey": {
      "id": 1,
      "device_name": "Adam's Windows Laptop",
      "transports": ["internal", "hybrid"],
      "authenticator_attachment": "platform",
      "backup_eligible": true,
      "backup_state": false,
      "last_used_at": null,
      "created_at": "2024-01-15T10:31:00+00:00"
    },
    "token": "1|abc123plainTextToken...",
    "token_type": "Bearer"
  }
}
```

### 4. Passkey Login Options (Email-First)

**Request:**
```http
POST /api/auth/passkey/login/options
Content-Type: application/json

{
  "email": "adam@example.com"
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Passkey authentication options generated.",
  "data": {
    "publicKey": {
      "challenge": "YW5vdGhlciByYW5kb20gY2hhbGxlbmdl",
      "timeout": 60000,
      "rpId": "localhost",
      "userVerification": "preferred",
      "allowCredentials": [
        {
          "type": "public-key",
          "id": "credential-id-base64url",
          "transports": ["internal", "hybrid"]
        }
      ]
    }
  }
}
```

### 5. Passkey Login Options (Discoverable / Username-less)

**Request:**
```http
POST /api/auth/passkey/login/options
Content-Type: application/json

{}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Passkey authentication options generated.",
  "data": {
    "publicKey": {
      "challenge": "c29tZSByYW5kb20gY2hhbGxlbmdl",
      "timeout": 60000,
      "rpId": "localhost",
      "userVerification": "preferred"
    }
  }
}
```

Note: No `allowCredentials` in the response - the authenticator uses a discoverable credential.

### 6. Passkey Login Verify

**Request:**
```http
POST /api/auth/passkey/login/verify
Content-Type: application/json

{
  "id": "credential-id-base64url",
  "rawId": "credential-id-base64url",
  "type": "public-key",
  "response": {
    "clientDataJSON": "base64url-encoded-client-data",
    "authenticatorData": "base64url-encoded-auth-data",
    "signature": "base64url-encoded-signature",
    "userHandle": "base64url-user-handle"
  },
  "authenticatorAttachment": "platform"
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Authenticated successfully.",
  "data": {
    "token": "2|xyz789plainTextToken...",
    "token_type": "Bearer",
    "user": {
      "id": 1,
      "name": "Adam",
      "email": "adam@example.com",
      "email_verified_at": null,
      "has_passkey": true,
      "has_password": true,
      "passkey_count": 1,
      "created_at": "2024-01-15T10:30:00+00:00",
      "updated_at": "2024-01-15T10:30:00+00:00"
    }
  }
}
```

### 7. Support Check

**Request:**
```http
GET /api/auth/passkey/support-check
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "passkey_enabled": true,
    "rp": {
      "id": "localhost",
      "name": "Passkey Auth API"
    },
    "allowed_origins": ["http://localhost:3000"],
    "preferences": {
      "user_verification": "preferred",
      "resident_key": "required",
      "attestation": "none",
      "authenticator_attachment": null,
      "timeout_ms": 60000
    },
    "supported_flows": {
      "discoverable_login": true,
      "email_first_login": true
    },
    "frontend_checks_required": {
      "description": "The backend cannot detect client-side WebAuthn support. The frontend MUST perform these checks before initiating passkey flows.",
      "checks": [
        {
          "name": "webauthn_available",
          "js": "typeof window.PublicKeyCredential !== 'undefined'",
          "description": "Basic WebAuthn API availability in the browser."
        },
        {
          "name": "platform_authenticator_available",
          "js": "PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()",
          "description": "Whether a platform authenticator (Touch ID, Windows Hello, etc.) is available."
        },
        {
          "name": "conditional_mediation_available",
          "js": "PublicKeyCredential.isConditionalMediationAvailable?.()",
          "description": "Whether the browser supports conditional mediation (autofill UI for passkeys)."
        }
      ]
    },
    "notes": [
      "The backend specifies the user_verification preference but does NOT control how the user is verified...",
      "Devices without biometric hardware may still support passkeys through their secure screen lock...",
      "The authenticator_attachment preference is a hint, not a guarantee..."
    ]
  }
}
```

### 8. Error Response Examples

```json
{
  "success": false,
  "message": "The challenge has expired. Please request a new one.",
  "error_code": "CHALLENGE_EXPIRED",
  "errors": {}
}
```

```json
{
  "success": false,
  "message": "Validation failed.",
  "error_code": "INVALID_REQUEST",
  "errors": {
    "email": ["The email field is required."]
  }
}
```

### Error Codes

| Code | Description |
|------|-------------|
| `PASSKEY_NOT_SUPPORTED` | WebAuthn not supported on client |
| `PASSKEY_BACKEND_DISABLED` | Passkey feature disabled in config |
| `INVALID_REQUEST` | Validation errors |
| `CHALLENGE_EXPIRED` | Challenge TTL exceeded |
| `CHALLENGE_ALREADY_USED` | Challenge replay attempt |
| `CHALLENGE_NOT_FOUND` | Unknown or mismatched challenge |
| `INVALID_ORIGIN` | Origin not in allowed list |
| `INVALID_RP_ID` | RP ID hash mismatch |
| `DUPLICATE_CREDENTIAL` | Credential already registered |
| `CREDENTIAL_NOT_FOUND` | Credential not in database |
| `PASSKEY_VERIFICATION_FAILED` | General verification failure |
| `SIGN_COUNT_MISMATCH` | Possible cloned authenticator |
| `UNAUTHORIZED` | Missing or invalid token |
| `LAST_PASSKEY_DELETION_NOT_ALLOWED` | Can't delete last credential without backup auth |
| `RATE_LIMIT_EXCEEDED` | Too many requests |

---

## Frontend Integration Guide

### Prerequisites

Use a WebAuthn client library such as:
- **[@simplewebauthn/browser](https://github.com/MasterKale/SimpleWebAuthn)** (recommended)
- **[@github/webauthn-json](https://github.com/nicbarker/webauthn-json)**
- Or vanilla JavaScript with the Web Authentication API

### Step 1: Check Browser Support

```javascript
async function checkPasskeySupport() {
  // Check 1: Basic WebAuthn API
  if (typeof window.PublicKeyCredential === 'undefined') {
    return { supported: false, reason: 'WebAuthn is not available in this browser.' };
  }

  // Check 2: Platform authenticator (Touch ID, Windows Hello, etc.)
  const platformAvailable = await PublicKeyCredential
    .isUserVerifyingPlatformAuthenticatorAvailable();

  // Check 3: Conditional mediation (autofill UI)
  let conditionalAvailable = false;
  if (typeof PublicKeyCredential.isConditionalMediationAvailable === 'function') {
    conditionalAvailable = await PublicKeyCredential.isConditionalMediationAvailable();
  }

  return {
    supported: true,
    platformAuthenticator: platformAvailable,
    conditionalMediation: conditionalAvailable,
  };
}
```

### Step 2: Fetch Backend Config

```javascript
const response = await fetch('/api/auth/passkey/support-check');
const { data } = await response.json();
// data.passkey_enabled, data.rp, data.preferences, etc.
```

### Step 3: Register a Passkey

```javascript
// Helper: Convert base64url string to ArrayBuffer
function base64urlToBuffer(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (base64.length % 4)) % 4;
  const padded = base64 + '='.repeat(padLen);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Helper: Convert ArrayBuffer to base64url string
function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function registerPasskey(userId) {
  // 1. Get registration options from the API
  const optionsRes = await fetch('/api/auth/passkey/register/options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_id: userId }),
  });
  const { data } = await optionsRes.json();
  const publicKey = data.publicKey;

  // 2. Convert base64url fields to ArrayBuffer for the browser API
  publicKey.challenge = base64urlToBuffer(publicKey.challenge);
  publicKey.user.id = new TextEncoder().encode(publicKey.user.id);
  if (publicKey.excludeCredentials) {
    publicKey.excludeCredentials = publicKey.excludeCredentials.map(cred => ({
      ...cred,
      id: base64urlToBuffer(cred.id),
    }));
  }

  // 3. Call the browser WebAuthn API
  //    The OS/browser will prompt the user for biometric, Windows Hello, device PIN, etc.
  //    The backend has NO control over which method is used - this is correct.
  let credential;
  try {
    credential = await navigator.credentials.create({ publicKey });
  } catch (err) {
    if (err.name === 'NotAllowedError') {
      console.log('User cancelled the passkey registration.');
      return;
    }
    throw err;
  }

  // 4. Serialize the response to send to the API
  const attestationResponse = {
    user_id: userId,
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
      attestationObject: bufferToBase64url(credential.response.attestationObject),
      transports: credential.response.getTransports?.() || [],
      publicKey: credential.response.getPublicKey
        ? bufferToBase64url(credential.response.getPublicKey())
        : undefined,
      authenticatorData: credential.response.getAuthenticatorData
        ? bufferToBase64url(credential.response.getAuthenticatorData())
        : undefined,
    },
    authenticatorAttachment: credential.authenticatorAttachment || undefined,
    device_name: 'My Device',  // Let the user name their device
  };

  // 5. Verify with the API
  const verifyRes = await fetch('/api/auth/passkey/register/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(attestationResponse),
  });
  const result = await verifyRes.json();

  if (result.success) {
    console.log('Passkey registered!', result.data);
    // If a token was returned (first registration), save it
    if (result.data.token) {
      localStorage.setItem('auth_token', result.data.token);
    }
  }
}
```

### Step 4: Login with Passkey

```javascript
async function loginWithPasskey(email = null) {
  // 1. Get authentication options
  const optionsRes = await fetch('/api/auth/passkey/login/options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }), // null for discoverable flow
  });
  const { data } = await optionsRes.json();
  const publicKey = data.publicKey;

  // 2. Convert base64url fields to ArrayBuffer
  publicKey.challenge = base64urlToBuffer(publicKey.challenge);
  if (publicKey.allowCredentials) {
    publicKey.allowCredentials = publicKey.allowCredentials.map(cred => ({
      ...cred,
      id: base64urlToBuffer(cred.id),
    }));
  }

  // 3. Call the browser WebAuthn API
  //    Again, the OS handles the actual authentication (fingerprint, Face ID, PIN, etc.)
  let assertion;
  try {
    assertion = await navigator.credentials.get({ publicKey });
  } catch (err) {
    if (err.name === 'NotAllowedError') {
      console.log('User cancelled the passkey authentication.');
      return;
    }
    throw err;
  }

  // 4. Serialize the assertion response
  const assertionResponse = {
    id: assertion.id,
    rawId: bufferToBase64url(assertion.rawId),
    type: assertion.type,
    response: {
      clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
      authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
      signature: bufferToBase64url(assertion.response.signature),
      userHandle: assertion.response.userHandle
        ? bufferToBase64url(assertion.response.userHandle)
        : null,
    },
    authenticatorAttachment: assertion.authenticatorAttachment || undefined,
  };

  // 5. Verify with the API
  const verifyRes = await fetch('/api/auth/passkey/login/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(assertionResponse),
  });
  const result = await verifyRes.json();

  if (result.success) {
    // Save the token
    localStorage.setItem('auth_token', result.data.token);
    console.log('Logged in as:', result.data.user.name);
  }
}
```

### Step 5: Using @simplewebauthn/browser (Recommended)

If you use the SimpleWebAuthn library, the serialization is handled for you:

```bash
npm install @simplewebauthn/browser
```

```javascript
import {
  startRegistration,
  startAuthentication,
} from '@simplewebauthn/browser';

// Registration
async function register(userId) {
  const optionsRes = await fetch('/api/auth/passkey/register/options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_id: userId }),
  });
  const { data } = await optionsRes.json();

  // SimpleWebAuthn handles all the ArrayBuffer conversions
  const attResp = await startRegistration(data.publicKey);

  const verifyRes = await fetch('/api/auth/passkey/register/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_id: userId, ...attResp, device_name: 'My Device' }),
  });
  return await verifyRes.json();
}

// Authentication
async function login(email = null) {
  const optionsRes = await fetch('/api/auth/passkey/login/options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  });
  const { data } = await optionsRes.json();

  const assertResp = await startAuthentication(data.publicKey);

  const verifyRes = await fetch('/api/auth/passkey/login/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(assertResp),
  });
  return await verifyRes.json();
}
```

### Handling Unsupported Devices

```javascript
async function initAuth() {
  const support = await checkPasskeySupport();

  if (!support.supported) {
    // Show traditional login form (email + password)
    showPasswordLoginForm();
    showMessage('Your browser does not support passkeys. Please use email and password.');
    return;
  }

  if (!support.platformAuthenticator) {
    // The device has WebAuthn but no platform authenticator.
    // May still work with a security key or through device sync.
    showPasskeyLoginForm();
    showMessage('Passkeys are supported. You may be prompted to use a security key or linked device.');
    return;
  }

  // Full support - show passkey login
  showPasskeyLoginForm();
}
```

---

## Authentication Flows

### Flow A: Registration + First Passkey

```
1. POST /api/auth/register              -> Creates user account
2. POST /api/auth/passkey/register/options -> Gets WebAuthn creation options
3. Frontend: navigator.credentials.create()  -> User verifies via OS prompt
4. POST /api/auth/passkey/register/verify    -> Server verifies & stores credential
   -> Returns Sanctum token
```

### Flow B: Passkey Login (Email-First)

```
1. POST /api/auth/passkey/login/options  -> Gets auth options with allowCredentials
   (include email in request body)
2. Frontend: navigator.credentials.get()   -> User authenticates via OS prompt
3. POST /api/auth/passkey/login/verify   -> Server verifies assertion
   -> Returns Sanctum token
```

### Flow C: Passkey Login (Discoverable / Username-less)

```
1. POST /api/auth/passkey/login/options  -> Gets auth options WITHOUT allowCredentials
   (omit email from request body)
2. Frontend: navigator.credentials.get()   -> Authenticator offers discoverable credentials
3. POST /api/auth/passkey/login/verify   -> Server verifies assertion, identifies user by credential
   -> Returns Sanctum token
```

### Flow D: Add Additional Passkey (Authenticated)

```
1. POST /api/auth/passkeys/add/options   -> Gets creation options (auth required)
   (Bearer token in header)
2. Frontend: navigator.credentials.create()  -> User verifies via OS prompt
3. POST /api/auth/passkeys/add/verify    -> Server verifies & stores additional credential
```

---

## Security Architecture

### Challenge Security

- **Cryptographically random**: 32 bytes from `random_bytes()`
- **Time-limited**: Configurable TTL (default 5 minutes)
- **Single-use**: Marked as consumed after verification (replay protection)
- **Server-side storage**: Challenges stored in database, not trusted from client alone
- **Flow-type separation**: Registration and authentication challenges are separate types

### Origin Validation

The `origin` field in `clientDataJSON` is verified against the `allowed_origins` configuration. This prevents phishing attacks where a malicious site tries to use credentials created for your domain.

### RP ID Validation

The authenticator data contains a SHA-256 hash of the Relying Party ID. The server verifies this matches the expected RP ID, ensuring the credential was created for our application.

### Signature Counter

After each authentication, the authenticator's signature counter is compared against the stored value. If the received counter is not greater than the stored counter, it may indicate a cloned authenticator. Note: synced passkeys may always report 0, which is handled gracefully.

### Why No Custom PIN System

**NEVER build a custom PIN authentication system to replace WebAuthn.** Here's why:

1. The WebAuthn standard already handles user verification through the platform authenticator
2. When biometrics are unavailable, the device's secure unlock (Windows Hello PIN, device passcode, etc.) is used automatically
3. A custom PIN stored in your database is:
   - Less secure (you become responsible for PIN storage and brute-force protection)
   - Redundant (the OS already provides this)
   - Non-standard (breaks interoperability)
4. The OS-level PIN/passcode is protected by hardware security modules (TPM, Secure Enclave)

---

## Testing Guide

### Testing on Different Platforms

#### Windows (Windows Hello)
1. Ensure Windows Hello is configured (Settings > Accounts > Sign-in options)
2. Test with fingerprint, face recognition, or Windows Hello PIN
3. The PIN here is the **Windows Hello PIN**, NOT a custom app PIN

#### Android (Chrome)
1. Test with fingerprint sensor
2. Test without fingerprint: device will prompt for PIN/pattern/password
3. Test with screen lock disabled: passkey registration should still work if the device supports it

#### iPhone / iPad (Safari)
1. Test with Face ID (iPhone X and later)
2. Test with Touch ID (older iPhones, iPads)
3. Test with device passcode fallback (when biometric fails)
4. Test iCloud Keychain sync between devices

#### macOS (Safari / Chrome)
1. Test with Touch ID on MacBook Pro/Air
2. Test with login password fallback on Mac mini/Pro (no Touch ID)

#### Cross-Device Authentication
1. Test scanning QR code from another device
2. Test Bluetooth-linked device authentication

### Testing Edge Cases

```bash
# Expired challenge: Wait > PASSKEY_CHALLENGE_TTL seconds between options and verify
# Expected: CHALLENGE_EXPIRED error

# Replay attack: Use the same challenge response twice
# Expected: CHALLENGE_ALREADY_USED error

# Wrong origin: Set PASSKEY_ALLOWED_ORIGINS to a different domain
# Expected: INVALID_ORIGIN error

# Duplicate credential: Try to register the same authenticator twice
# Expected: DUPLICATE_CREDENTIAL error

# Deleted credential: Delete a passkey, then try to log in with it
# Expected: CREDENTIAL_NOT_FOUND error

# Last passkey deletion: Try to delete the only passkey without a password set
# Expected: LAST_PASSKEY_DELETION_NOT_ALLOWED error
```

### Automated Testing

```bash
# Run the test suite
php artisan test

# Test specific feature
php artisan test --filter=PasskeyRegistrationTest
```

---

## Production Deployment

### Checklist

- [ ] Set `APP_ENV=production` and `APP_DEBUG=false`
- [ ] Set `PASSKEY_RP_ID` to your actual domain (e.g., `example.com`)
- [ ] Set `PASSKEY_ALLOWED_ORIGINS` to your production URL (e.g., `https://example.com`)
- [ ] Set `PASSKEY_STRICT_ORIGIN=true`
- [ ] Set `PASSKEY_USER_VERIFICATION=preferred` (or `required` for high-security)
- [ ] Ensure HTTPS is enabled (WebAuthn requires secure context except on localhost)
- [ ] Configure the scheduled task for challenge cleanup
- [ ] Set appropriate rate limits
- [ ] Configure CORS for your frontend domain
- [ ] Review and set `SANCTUM_STATEFUL_DOMAINS`
- [ ] Use a strong `APP_KEY`

### HTTPS Requirement

WebAuthn requires a **secure context** (HTTPS) in production. Browsers will refuse to call `navigator.credentials.create()` or `navigator.credentials.get()` on HTTP pages (localhost is the only exception).

### RP ID Rules

- The RP ID must be a valid domain or a registrable domain suffix of the current origin
- If your frontend is at `https://app.example.com`, valid RP IDs are: `app.example.com` or `example.com`
- You CANNOT use `example.com` as RP ID if the page is served from `otherdomain.com`
- Once set, changing the RP ID will invalidate all existing credentials

---

## Troubleshooting

### "Origin validation failed"

- Check that `PASSKEY_ALLOWED_ORIGINS` includes the exact origin (protocol + domain + port)
- For local dev: `http://localhost:3000` (not `http://localhost:3000/`)
- For production: `https://example.com` (must include `https://`)

### "RP ID validation failed"

- Check that `PASSKEY_RP_ID` matches the domain the frontend is served from
- For local dev: use `localhost`
- For production: use your domain without protocol (e.g., `example.com`)

### "Challenge expired"

- Increase `PASSKEY_CHALLENGE_TTL` if ceremonies are timing out
- Ensure server clocks are synchronized (NTP)

### "NotAllowedError" in browser

- User cancelled the WebAuthn prompt
- WebAuthn is blocked by browser permissions
- Not using HTTPS (required in production)

### "No platform authenticator available"

- The device doesn't have a built-in authenticator (no fingerprint reader, no secure enclave)
- A security key (USB/NFC) can still be used if `authenticator_attachment` is not set to `platform`

### Passkeys not syncing between devices

- Ensure `resident_key` is set to `required`
- Syncing depends on the platform (iCloud Keychain, Google Password Manager, etc.)
- The backend does NOT control sync behavior - this is platform-managed
