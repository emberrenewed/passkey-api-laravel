<?php

use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return response(file_get_contents(public_path('index.html')), 200)
        ->header('Content-Type', 'text/html');
})->withoutMiddleware(\Illuminate\Session\Middleware\StartSession::class);
