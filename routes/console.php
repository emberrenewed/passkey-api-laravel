<?php

use Illuminate\Support\Facades\Schedule;

// Purge expired WebAuthn challenges every hour.
Schedule::command('passkey:purge-challenges')->hourly();
