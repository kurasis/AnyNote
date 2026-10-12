<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\CapabilitiesController;
use App\Http\Controllers\DevicesController;
use App\Http\Controllers\OperatorReadinessController;
use App\Http\Controllers\ReadinessController;
use Illuminate\Support\Facades\Route;

Route::get('/health/ready', ReadinessController::class);
Route::get('/api/v1/capabilities', CapabilitiesController::class)->name('get_capabilities');
Route::get('/api/v1/health/live', fn () => response()->json(['status' => 'live']))->name('get_health_live');
// Product content APIs retain their later phase ownership.
Route::get('/api/v1/health/ready', OperatorReadinessController::class)->name('get_health_ready');

Route::get('/api/v1/auth/csrf', AuthController::class)->name('get_auth_csrf');
Route::post('/api/v1/auth/passkeys/options', AuthController::class)->name('post_auth_passkeys_options');
Route::post('/api/v1/auth/passkeys/verify', AuthController::class)->name('post_auth_passkeys_verify');
Route::post('/api/v1/accounts/registration-challenge', AuthController::class)->name('post_accounts_registration_challenge');
Route::post('/api/v1/accounts/register', AuthController::class)->name('post_accounts_register');
Route::post('/api/v1/auth/device-challenge', AuthController::class)->name('post_auth_device_challenge');
Route::post('/api/v1/auth/device-proof', AuthController::class)->name('post_auth_device_proof');
Route::post('/api/v1/auth/recovery-code', AuthController::class)->name('post_auth_recovery_code');
Route::post('/api/v1/auth/logout', AuthController::class)->name('post_auth_logout');
Route::get('/api/v1/me', AuthController::class)->name('get_me');
Route::get('/api/v1/me/sessions', AuthController::class)->name('get_me_sessions');
Route::delete('/api/v1/me/sessions/{id}', AuthController::class)->name('delete_me_sessions_id');
Route::get('/api/v1/me/passkeys', AuthController::class)->name('get_me_passkeys');
Route::delete('/api/v1/me/passkeys/{id}', AuthController::class)->name('delete_me_passkeys_id');
Route::post('/api/v1/me/recovery-codes', AuthController::class)->name('post_me_recovery_codes');
Route::get('/api/v1/auth/native/authorize', AuthController::class)->name('get_auth_native_authorize');
Route::get('/api/v1/auth/native/authorizations/{id}', AuthController::class)->name('get_auth_native_authorizations_id');
Route::post('/api/v1/auth/native/approve', AuthController::class)->name('post_auth_native_approve');
Route::post('/api/v1/auth/native/token', AuthController::class)->name('post_auth_native_token');
Route::post('/api/v1/admin/account-invitations', AuthController::class)->name('post_admin_account_invitations');
Route::post('/api/v1/admin/accounts/{id}/disable', AuthController::class)->name('post_admin_accounts_id_disable');

Route::post('/api/v1/me/passkeys', AuthController::class)->name('post_me_passkeys');
Route::delete('/api/v1/me/sessions', AuthController::class)->name('delete_me_sessions');

// P08 current-device lifecycle and account-private settings genesis.
Route::get('/api/v1/accounts/{id}/identity', DevicesController::class)->name('get_accounts_id_identity');
Route::get('/api/v1/accounts/{id}/roster', DevicesController::class)->name('get_accounts_id_roster');
Route::get('/api/v1/me/devices', DevicesController::class)->name('get_me_devices');
Route::post('/api/v1/me/devices/{id}/revoke', DevicesController::class)->name('post_me_devices_id_revoke');
Route::post('/api/v1/me/enrollments', DevicesController::class)->name('post_me_enrollments');
Route::post('/api/v1/me/enrollments/{id}/approve', DevicesController::class)->name('post_me_enrollments_id_approve');
Route::post('/api/v1/me/enrollments/{id}/confirm', DevicesController::class)->name('post_me_enrollments_id_confirm');
Route::get('/api/v1/me/enrollments/{id}/relay', DevicesController::class)->name('get_me_enrollments_id_relay');
Route::post('/api/v1/me/enrollments/{id}/relay', DevicesController::class)->name('post_me_enrollments_id_relay');
Route::post('/api/v1/me/recovery-challenge', DevicesController::class)->name('post_me_recovery_challenge');
Route::post('/api/v1/me/recovery-reset', DevicesController::class)->name('post_me_recovery_reset');
Route::delete('/api/v1/me/enrollments/{id}', DevicesController::class)->name('delete_me_enrollments_id');
Route::post('/api/v1/me/settings-genesis', DevicesController::class)->name('post_me_settings_genesis');
Route::get('/api/v1/me/settings-genesis', DevicesController::class)->name('get_me_settings_genesis');
Route::post('/api/v1/me/device-envelopes', DevicesController::class)->name('post_me_device_envelopes');
Route::get('/api/v1/me/device-envelopes', DevicesController::class)->name('get_me_device_envelopes');
Route::get('/api/v1/me/recovery-envelopes', DevicesController::class)->name('get_me_recovery_envelopes');
Route::get('/api/v1/me/security-notifications', DevicesController::class)->name('get_me_security_notifications');
