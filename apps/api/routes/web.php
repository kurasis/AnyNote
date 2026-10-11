<?php

use App\Http\Controllers\ReadinessController;
use Illuminate\Support\Facades\Route;

// Tooling-only readiness; no product/authentication endpoints are scaffolded.
Route::get('/health/ready', ReadinessController::class);
