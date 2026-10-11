<?php

use App\Http\Controllers\CapabilitiesController;
use App\Http\Controllers\ReadinessController;
use Illuminate\Support\Facades\Route;

Route::get('/health/ready', ReadinessController::class);
Route::get('/api/v1/capabilities', CapabilitiesController::class)->name('get_capabilities');
Route::get('/api/v1/health/live', fn () => response()->json(['status' => 'live']))->name('get_health_live');
// Future product/authentication paths in OpenAPI have no executable stub here.
