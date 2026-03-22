<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

$app = Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__ . '/../routes/web.php',
        api: __DIR__ . '/../routes/api.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware) {
        // Remove session/cookie middleware from web group since this is an API-only project.
        $middleware->web(remove: [
            \Illuminate\Session\Middleware\StartSession::class,
            \Illuminate\View\Middleware\ShareErrorsFromSession::class,
            \Illuminate\Foundation\Http\Middleware\ValidateCsrfToken::class,
            \Illuminate\Cookie\Middleware\EncryptCookies::class,
            \Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse::class,
        ]);

        $middleware->api(prepend: [
            \Laravel\Sanctum\Http\Middleware\EnsureFrontendRequestsAreStateful::class,
        ]);

        $middleware->alias([
            'passkey.enabled' => \App\Http\Middleware\EnsurePasskeyEnabled::class,
            'throttle.passkey' => \App\Http\Middleware\ThrottlePasskeyAttempts::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions) {
        $exceptions->renderable(function (\App\Exceptions\WebAuthnException $e) {
            return response()->json([
                'success' => false,
                'message' => $e->getMessage(),
                'error_code' => $e->getErrorCode(),
                'errors' => $e->getValidationErrors(),
            ], $e->getHttpStatusCode());
        });

        $exceptions->renderable(function (\Illuminate\Auth\AuthenticationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthenticated.',
                'error_code' => 'UNAUTHORIZED',
            ], 401);
        });

        $exceptions->renderable(function (\Illuminate\Validation\ValidationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed.',
                'error_code' => 'INVALID_REQUEST',
                'errors' => $e->errors(),
            ], 422);
        });

        $exceptions->renderable(function (\Symfony\Component\HttpKernel\Exception\NotFoundHttpException $e, \Illuminate\Http\Request $request) {
            if ($request->is('api/*') || $request->wantsJson()) {
                return response()->json([
                    'success' => false,
                    'message' => 'Resource not found.',
                    'error_code' => 'NOT_FOUND',
                ], 404);
            }
        });

        $exceptions->renderable(function (\Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Too many requests. Please try again later.',
                'error_code' => 'RATE_LIMIT_EXCEEDED',
            ], 429);
        });
    })->create();

// Vercel serverless: use /tmp for writable paths since the filesystem is read-only.
if (isset($_ENV['VERCEL']) || getenv('VERCEL')) {
    $app->useStoragePath('/tmp/storage');

    // Create required directories
    foreach ([
        '/tmp/storage/framework/views',
        '/tmp/storage/framework/cache',
        '/tmp/storage/framework/sessions',
        '/tmp/storage/logs',
        '/tmp/database',
    ] as $dir) {
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
    }

    // Auto-create SQLite database and run migrations on each cold start.
    // This makes the demo work without an external database.
    // Data resets on each cold start — this is expected for a demo.
    $dbPath = '/tmp/database/database.sqlite';
    if (!file_exists($dbPath)) {
        touch($dbPath);
        // Run migrations after Laravel boots
        $app->booted(function () {
            try {
                \Illuminate\Support\Facades\Artisan::call('migrate', ['--force' => true]);
            } catch (\Throwable $e) {
                // Silently fail — log if possible
                \Illuminate\Support\Facades\Log::error('Auto-migration failed: ' . $e->getMessage());
            }
        });
    }
}

return $app;
