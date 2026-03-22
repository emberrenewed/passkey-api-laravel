<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('passkey_credentials', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')
                ->constrained('users')
                ->cascadeOnDelete();

            // The credential ID from the authenticator, stored as base64url.
            // This uniquely identifies a credential globally.
            $table->text('credential_id');

            // The public key associated with this credential, stored as base64url-encoded CBOR/COSE.
            // NEVER store the private key - it lives only on the authenticator device.
            $table->text('credential_public_key');

            // Signature counter to help detect cloned authenticators.
            // After each authentication, the counter must be >= the stored value.
            $table->unsignedBigInteger('sign_count')->default(0);

            // Transport hints (e.g., ["internal", "hybrid"]) - helps the browser
            // know how to reach this authenticator in future ceremonies.
            $table->json('transports')->nullable();

            // AAGUID identifies the authenticator model (not the individual device).
            $table->string('aaguid')->nullable();

            // User-assigned friendly name for this credential/device.
            $table->string('device_name')->nullable();

            // Attestation format used during registration (e.g., "none", "packed").
            $table->string('attestation_format')->nullable();

            // Whether this was a platform or cross-platform authenticator.
            $table->string('authenticator_attachment')->nullable();

            // The user handle sent to the authenticator (typically the user's UUID or ID).
            $table->string('user_handle')->nullable();

            // Whether the credential is eligible for multi-device sync (e.g., iCloud Keychain, Google Password Manager).
            $table->boolean('backup_eligible')->nullable();

            // Whether the credential is currently synced/backed up.
            $table->boolean('backup_state')->nullable();

            // Last time this credential was used for authentication.
            $table->timestamp('last_used_at')->nullable();

            $table->timestamps();
            $table->softDeletes();

            // Index for fast lookup during authentication.
            // credential_id is TEXT so we use a hash index approach via a virtual column.
            $table->index('user_id');
        });

        // Add a generated column for indexing credential_id lookups efficiently.
        // MySQL can't directly index TEXT, so we hash it.
        if (config('database.default') === 'mysql') {
            \Illuminate\Support\Facades\DB::statement(
                'ALTER TABLE passkey_credentials ADD COLUMN credential_id_hash VARCHAR(64) GENERATED ALWAYS AS (SHA2(credential_id, 256)) STORED'
            );
            \Illuminate\Support\Facades\DB::statement(
                'CREATE UNIQUE INDEX idx_credential_id_hash ON passkey_credentials (credential_id_hash)'
            );
        }
    }

    public function down(): void
    {
        Schema::dropIfExists('passkey_credentials');
    }
};
