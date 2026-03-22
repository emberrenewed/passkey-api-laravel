<?php

use App\Http\Controllers\Api\Auth\LoginController;
use App\Http\Controllers\Api\Auth\LogoutController;
use App\Http\Controllers\Api\Auth\MeController;
use App\Http\Controllers\Api\Auth\PasskeyAuthenticationController;
use App\Http\Controllers\Api\Auth\PasskeyManagementController;
use App\Http\Controllers\Api\Auth\PasskeyRegistrationController;
use App\Http\Controllers\Api\Auth\PasskeySupportController;
use App\Http\Controllers\Api\Auth\RegisterController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| All routes are prefixed with /api by Laravel's routing configuration.
|
*/

Route::prefix('auth')->group(function () {

    // ──────────────────────────────────────────────────────
    // PUBLIC ROUTES (no authentication required)
    // ──────────────────────────────────────────────────────

    // Account registration.
    Route::post('/register', RegisterController::class)
        ->middleware('throttle:10,1')
        ->name('auth.register');

    // Passkey support check - returns backend config for the frontend.
    Route::get('/passkey/support-check', PasskeySupportController::class)
        ->middleware('passkey.enabled')
        ->name('auth.passkey.support-check');

    // Passkey registration (initial setup after account creation).
    Route::middleware(['passkey.enabled', 'throttle.passkey'])->group(function () {
        Route::post('/passkey/register/options', [PasskeyRegistrationController::class, 'options'])
            ->name('auth.passkey.register.options');

        Route::post('/passkey/register/verify', [PasskeyRegistrationController::class, 'verify'])
            ->name('auth.passkey.register.verify');
    });

    // Passkey authentication (login).
    Route::middleware(['passkey.enabled', 'throttle.passkey'])->group(function () {
        Route::post('/passkey/login/options', [PasskeyAuthenticationController::class, 'options'])
            ->name('auth.passkey.login.options');

        Route::post('/passkey/login/verify', [PasskeyAuthenticationController::class, 'verify'])
            ->name('auth.passkey.login.verify');
    });

    // Optional backup: password-based login.
    Route::post('/login/password', LoginController::class)
        ->middleware('throttle:5,1')
        ->name('auth.login.password');

    // ──────────────────────────────────────────────────────
    // AUTHENTICATED ROUTES (Sanctum token required)
    // ──────────────────────────────────────────────────────

    Route::middleware('auth:sanctum')->group(function () {
        // User profile.
        Route::get('/me', MeController::class)
            ->name('auth.me');

        // Logout (revoke current token).
        Route::post('/logout', LogoutController::class)
            ->name('auth.logout');

        // Passkey management.
        Route::get('/passkeys', [PasskeyManagementController::class, 'index'])
            ->name('auth.passkeys.index');

        Route::patch('/passkeys/{id}', [PasskeyManagementController::class, 'update'])
            ->name('auth.passkeys.update');

        Route::delete('/passkeys/{id}', [PasskeyManagementController::class, 'destroy'])
            ->name('auth.passkeys.destroy');

        // Add additional passkey (for already authenticated users).
        Route::middleware('passkey.enabled')->group(function () {
            Route::post('/passkeys/add/options', [PasskeyRegistrationController::class, 'addOptions'])
                ->name('auth.passkeys.add.options');

            Route::post('/passkeys/add/verify', [PasskeyRegistrationController::class, 'addVerify'])
                ->name('auth.passkeys.add.verify');
        });
    });
});
