<?php

namespace App\Providers;

use App\Services\Auth\Passkey\ChallengeService;
use App\Services\Auth\Passkey\PasskeyAuthenticationService;
use App\Services\Auth\Passkey\PasskeyRegistrationService;
use App\Services\Auth\Passkey\PasskeySupportService;
use App\Services\Auth\Passkey\TokenService;
use App\Services\Auth\Passkey\WebAuthnConfigService;
use Illuminate\Support\ServiceProvider;

class WebAuthnServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // Register all WebAuthn services as singletons for performance.
        $this->app->singleton(WebAuthnConfigService::class);
        $this->app->singleton(ChallengeService::class);
        $this->app->singleton(PasskeyRegistrationService::class);
        $this->app->singleton(PasskeyAuthenticationService::class);
        $this->app->singleton(PasskeySupportService::class);
        $this->app->singleton(TokenService::class);
    }

    public function boot(): void
    {
        //
    }
}
