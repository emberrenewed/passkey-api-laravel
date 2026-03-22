<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('webauthn_challenges', function (Blueprint $table) {
            $table->id();

            // Nullable because discoverable-credential login challenges are not
            // associated with a specific user until the assertion is verified.
            $table->foreignId('user_id')
                ->nullable()
                ->constrained('users')
                ->cascadeOnDelete();

            // The type of WebAuthn ceremony this challenge belongs to.
            // Separating challenge types prevents cross-ceremony replay attacks.
            $table->string('flow_type'); // 'registration' or 'authentication'

            // The challenge value itself - a cryptographically random base64url string.
            // Stored server-side and validated against the client response.
            $table->string('challenge');

            // When this challenge expires. Challenges MUST be time-limited to prevent replay.
            $table->timestamp('expires_at');

            // When this challenge was consumed (used). A consumed challenge cannot be reused.
            // This is critical for replay protection.
            $table->timestamp('consumed_at')->nullable();

            // Optional metadata for the challenge context (e.g., IP address, session info).
            $table->json('context')->nullable();

            $table->timestamps();

            $table->index(['challenge', 'flow_type']);
            $table->index('expires_at');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('webauthn_challenges');
    }
};
