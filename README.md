<p align="center">
  <img src="https://img.shields.io/badge/Laravel-11-FF2D20?style=for-the-badge&logo=laravel&logoColor=white" />
  <img src="https://img.shields.io/badge/PHP-8.2+-777BB4?style=for-the-badge&logo=php&logoColor=white" />
  <img src="https://img.shields.io/badge/WebAuthn-FIDO2-3B82F6?style=for-the-badge&logo=webauthn&logoColor=white" />
  <img src="https://img.shields.io/badge/Passkeys-Ready-10B981?style=for-the-badge&logo=keycdn&logoColor=white" />
</p>

<h1 align="center">Passkey Auth API</h1>

<p align="center">
  <strong>Production-ready passwordless authentication API built with Laravel & WebAuthn</strong>
</p>

<p align="center">
  Real passkey authentication using fingerprint, Face ID, Windows Hello, or device PIN.<br/>
  No fake PIN systems. No mock logic. Real WebAuthn/FIDO2 standard.
</p>

<p align="center">
  <a href="#features">Features</a> &bull;
  <a href="#tech-stack">Tech Stack</a> &bull;
  <a href="#api-endpoints">API Endpoints</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#how-it-works">How It Works</a> &bull;
  <a href="#deployment">Deployment</a>
</p>

---

## Features

- **Real Passkey Authentication** &mdash; WebAuthn/FIDO2 standard, not a simulation
- **Fingerprint & Face ID** &mdash; Works with Touch ID, Face ID, Windows Hello, Android biometrics
- **Device PIN Fallback** &mdash; OS handles secure unlock when biometrics aren't available
- **Username-less Login** &mdash; Discoverable credentials for one-tap sign in
- **Email-first Login** &mdash; Traditional flow with passkey verification
- **Multiple Passkeys** &mdash; Register and manage multiple devices per user
- **Device Management** &mdash; Rename, delete, and track passkey usage
- **Sanctum Tokens** &mdash; Secure API token issuance after authentication
- **Challenge Security** &mdash; Time-limited, single-use, server-stored challenges
- **Replay Protection** &mdash; Sign count validation to detect cloned authenticators
- **Audit Logging** &mdash; Security event tracking for all auth operations
- **Animated UI** &mdash; Tailwind CSS + GSAP with fingerprint/Face ID animations
- **Password Backup** &mdash; Optional password login as fallback

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Framework** | Laravel 11 |
| **Language** | PHP 8.2+ |
| **Auth Standard** | WebAuthn / FIDO2 / Passkeys |
| **API Tokens** | Laravel Sanctum |
| **Database** | MySQL / SQLite |
| **Frontend** | Tailwind CSS + GSAP |
| **Deployment** | Vercel (serverless PHP) |

## API Endpoints

### Public

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/register` | Create new account |
| `POST` | `/api/auth/passkey/register/options` | Get passkey registration options |
| `POST` | `/api/auth/passkey/register/verify` | Verify passkey registration |
| `POST` | `/api/auth/passkey/login/options` | Get passkey login options |
| `POST` | `/api/auth/passkey/login/verify` | Verify passkey login |
| `GET` | `/api/auth/passkey/support-check` | Check backend passkey config |
| `POST` | `/api/auth/login/password` | Password login (backup) |

### Authenticated (Bearer Token)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/auth/me` | Get current user profile |
| `POST` | `/api/auth/logout` | Revoke current token |
| `GET` | `/api/auth/passkeys` | List user's passkeys |
| `PATCH` | `/api/auth/passkeys/{id}` | Rename a passkey |
| `DELETE` | `/api/auth/passkeys/{id}` | Delete a passkey |
| `POST` | `/api/auth/passkeys/add/options` | Add passkey options |
| `POST` | `/api/auth/passkeys/add/verify` | Add passkey verify |

## Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/emberrenewed/passkey-api-laravel.git
cd passkey-api-laravel
composer install
cp .env.example .env
php artisan key:generate
```

### 2. Database Setup

**Option A: Docker (recommended)**
```bash
docker compose up -d
# MySQL on localhost:3306
# phpMyAdmin on localhost:8080
```

**Option B: Local MySQL**
```bash
# Update .env with your MySQL credentials
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_DATABASE=passkey_auth
DB_USERNAME=root
DB_PASSWORD=
```

### 3. Migrate & Serve

```bash
php artisan migrate
php artisan serve
```

Open **http://localhost:8000** and try it out!

## How It Works

### Registration Flow

```
User                    Frontend                  Backend
 |                         |                         |
 |-- Create Account ------>|-- POST /register ------>|
 |                         |<---- user created ------|
 |                         |                         |
 |                         |-- POST /register/options>|
 |                         |<-- challenge + config ---|
 |                         |                         |
 |<- Biometric Prompt -----|                         |
 |-- Fingerprint/Face ---->|                         |
 |                         |-- POST /register/verify->|
 |                         |<-- passkey saved + token-|
 |                         |                         |
```

### Login Flow

```
User                    Frontend                  Backend
 |                         |                         |
 |                         |-- POST /login/options -->|
 |                         |<-- challenge ------------|
 |                         |                         |
 |<- Biometric Prompt -----|                         |
 |-- Fingerprint/Face ---->|                         |
 |                         |-- POST /login/verify --->|
 |                         |<-- token + user ---------|
 |                         |                         |
```

### Security Architecture

- **Challenges**: Cryptographically random, time-limited (5 min), single-use
- **Origin Validation**: Strict verification of request origin
- **RP ID Validation**: Relying Party ID must match configured domain
- **Sign Counter**: Incremented each use, detects cloned authenticators
- **No PIN Storage**: Device OS handles all biometric/PIN verification
- **Token Security**: Laravel Sanctum tokens issued only after WebAuthn verification

## Project Structure

```
app/
  Http/
    Controllers/Api/Auth/
      RegisterController.php
      LoginController.php
      PasskeyRegistrationController.php
      PasskeyAuthenticationController.php
      PasskeyManagementController.php
      PasskeySupportController.php
    Requests/Auth/          # Form validation
    Resources/              # API transformers
    Middleware/              # Passkey & rate limiting
  Models/
    User.php
    PasskeyCredential.php
    WebauthnChallenge.php
    AuditLog.php
  Services/Auth/Passkey/
    WebAuthnConfigService.php
    ChallengeService.php
    PasskeyRegistrationService.php
    PasskeyAuthenticationService.php
    PasskeySupportService.php
    TokenService.php
  Exceptions/               # Custom WebAuthn exceptions
  Enums/                    # Error codes & flow types
config/
  passkeys.php              # WebAuthn configuration
```

## Configuration

Key `.env` variables:

```env
PASSKEY_RP_ID=yourdomain.com
PASSKEY_RP_NAME="Your App"
PASSKEY_ALLOWED_ORIGINS=https://yourdomain.com
PASSKEY_CHALLENGE_TTL=300
PASSKEY_USER_VERIFICATION=preferred
PASSKEY_RESIDENT_KEY=required
PASSKEY_ATTESTATION=none
```

## Deployment

### Vercel

The project includes `vercel.json` for serverless PHP deployment:

```bash
# Push to GitHub, Vercel auto-deploys
git push origin main
```

Set environment variables in Vercel Dashboard:
- `APP_KEY`, `APP_URL`
- `PASSKEY_RP_ID`, `PASSKEY_ALLOWED_ORIGINS`
- Database credentials (for production)

### Platform Support

| Platform | Biometric | Fallback |
|----------|-----------|----------|
| **iPhone/iPad** | Face ID / Touch ID | Device passcode |
| **Android** | Fingerprint / Face | PIN / Pattern |
| **Windows** | Windows Hello | PIN |
| **macOS** | Touch ID | Login password |

## License

MIT

---

<p align="center">
  Built with Laravel & WebAuthn &mdash; Real passkeys, no shortcuts.
</p>
