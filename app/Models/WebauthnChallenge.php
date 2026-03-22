<?php

namespace App\Models;

use App\Enums\WebauthnFlowType;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class WebauthnChallenge extends Model
{
    protected $fillable = [
        'user_id',
        'flow_type',
        'challenge',
        'expires_at',
        'consumed_at',
        'context',
    ];

    protected function casts(): array
    {
        return [
            'flow_type' => WebauthnFlowType::class,
            'expires_at' => 'datetime',
            'consumed_at' => 'datetime',
            'context' => 'array',
        ];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Check if this challenge has expired.
     */
    public function isExpired(): bool
    {
        return $this->expires_at->isPast();
    }

    /**
     * Check if this challenge has already been consumed (used).
     * A consumed challenge must NEVER be reused - this prevents replay attacks.
     */
    public function isConsumed(): bool
    {
        return !is_null($this->consumed_at);
    }

    /**
     * Check if this challenge is still valid (not expired and not consumed).
     */
    public function isValid(): bool
    {
        return !$this->isExpired() && !$this->isConsumed();
    }

    /**
     * Mark this challenge as consumed. Once consumed, it cannot be used again.
     */
    public function markConsumed(): void
    {
        $this->update(['consumed_at' => now()]);
    }

    /**
     * Scope to find valid (unexpired, unconsumed) challenges.
     */
    public function scopeValid($query)
    {
        return $query->where('expires_at', '>', now())
            ->whereNull('consumed_at');
    }

    /**
     * Scope to find expired challenges (for cleanup).
     */
    public function scopeExpired($query)
    {
        return $query->where('expires_at', '<=', now());
    }
}
