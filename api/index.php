<?php

/**
 * Vercel Serverless Function Entry Point
 *
 * This file bootstraps the Laravel application for Vercel's
 * serverless PHP runtime. All requests are routed through here.
 */

require __DIR__ . '/../vendor/autoload.php';

$app = require_once __DIR__ . '/../bootstrap/app.php';

$app->handleRequest(Illuminate\Http\Request::capture());
