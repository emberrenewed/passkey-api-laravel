<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable;

    protected $fillable = [
        'name',
        'email',
        'password',
    ];

    protected $hidden = [
        'password',
        'remember_token',
    ];

    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
        ];
    }

    /**
     * Get all passkey credentials registered by this user.
     */
    public function passkeyCredentials(): HasMany
    {
        return $this->hasMany(PasskeyCredential::class);
    }

    /**
     * Get active (non-deleted) passkey credentials.
     */
    public function activePasskeyCredentials(): HasMany
    {
        return $this->passkeyCredentials()->whereNull('deleted_at');
    }

    /**
     * Get all WebAuthn challenges associated with this user.
     */
    public function webauthnChallenges(): HasMany
    {
        return $this->hasMany(WebauthnChallenge::class);
    }

    /**
     * Check if the user has at least one registered passkey.
     */
    public function hasPasskey(): bool
    {
        return $this->activePasskeyCredentials()->exists();
    }

    /**
     * Check if the user has a password set (backup auth method).
     */
    public function hasPassword(): bool
    {
        return !is_null($this->password);
    }

    /**
     * Get the user handle for WebAuthn (a stable, non-PII identifier).
     * Using the user's ID ensures it's unique and doesn't leak personal info
     * to the authenticator.
     */
    public function getWebAuthnUserHandle(): string
    {
        return (string) $this->id;
    }
}
