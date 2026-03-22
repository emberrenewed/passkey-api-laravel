<?php

namespace App\Console\Commands;

use App\Services\Auth\Passkey\ChallengeService;
use Illuminate\Console\Command;

/**
 * Artisan command to purge expired WebAuthn challenges from the database.
 * Should be scheduled to run periodically (e.g., hourly) to keep the table clean.
 *
 * Usage: php artisan passkey:purge-challenges
 * Schedule: $schedule->command('passkey:purge-challenges')->hourly();
 */
class PurgeExpiredChallenges extends Command
{
    protected $signature = 'passkey:purge-challenges';
    protected $description = 'Remove expired WebAuthn challenges from the database';

    public function handle(ChallengeService $challengeService): int
    {
        $count = $challengeService->purgeExpired();

        $this->info("Purged {$count} expired challenge(s).");

        return self::SUCCESS;
    }
}
