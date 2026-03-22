<?php

/**
 * Vercel Serverless Function Entry Point
 *
 * All requests are routed here via vercel.json rewrites.
 * We must fix SERVER vars so Laravel sees the real URI, not /api/index.php.
 */

// Fix the script name so Laravel doesn't think it's nested under /api
$_SERVER['SCRIPT_NAME'] = '/index.php';
$_SERVER['SCRIPT_FILENAME'] = __DIR__ . '/../public/index.php';
$_SERVER['PHP_SELF'] = $_SERVER['REQUEST_URI'] ?? '/';

require __DIR__ . '/../vendor/autoload.php';

$app = require_once __DIR__ . '/../bootstrap/app.php';

$app->handleRequest(Illuminate\Http\Request::capture());
