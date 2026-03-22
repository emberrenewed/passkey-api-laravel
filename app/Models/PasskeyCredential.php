<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\SoftDeletes;

class PasskeyCredential extends Model
{
    use SoftDeletes;

    protected $fillable = [
        'user_id',
        'credential_id',
        'credential_public_key',
        'sign_count',
        'transports',
        'aaguid',
        'device_name',
        'attestation_format',
        'authenticator_attachment',
        'user_handle',
        'backup_eligible',
        'backup_state',
        'last_used_at',
    ];

    protected function casts(): array
    {
        return [
            'sign_count' => 'integer',
            'transports' => 'array',
            'backup_eligible' => 'boolean',
            'backup_state' => 'boolean',
            'last_used_at' => 'datetime',
            'created_at' => 'datetime',
            'updated_at' => 'datetime',
            'deleted_at' => 'datetime',
        ];
    }

    /**
     * The user who owns this credential.
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Mark this credential as just used.
     */
    public function markAsUsed(): void
    {
        $this->update(['last_used_at' => now()]);
    }

    /**
     * Update the signature counter after a successful authentication.
     *
     * The signature counter is a security mechanism: the authenticator increments
     * it on every use. If the stored count is ever higher than what the authenticator
     * reports, it may indicate a cloned authenticator.
     */
    public function updateSignCount(int $newCount): void
    {
        $this->update(['sign_count' => $newCount]);
    }
}
