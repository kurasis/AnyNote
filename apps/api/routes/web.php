<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\CapabilitiesController;
use App\Http\Controllers\DevicesController;
use App\Http\Controllers\FilesController;
use App\Http\Controllers\GroupsController;
use App\Http\Controllers\NotesController;
use App\Http\Controllers\OperatorReadinessController;
use App\Http\Controllers\ReadinessController;
use App\Http\Controllers\SyncController;
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

// P09 account-private E2EE content; shared policy transitions remain P10.
Route::post('/api/v1/groups/{id}/snapshots', SyncController::class)->name('post_groups_id_snapshots');
Route::get('/api/v1/mutations/{operation_id}', SyncController::class)->name('get_mutations_operation_id');
Route::post('/api/v1/snapshots', SyncController::class)->name('post_snapshots');
Route::delete('/api/v1/snapshots/{id}', SyncController::class)->name('delete_snapshots_id');
Route::get('/api/v1/snapshots/{id}/pages', SyncController::class)->name('get_snapshots_id_pages');
Route::post('/api/v1/snapshots/{id}/renew', SyncController::class)->name('post_snapshots_id_renew');
Route::get('/api/v1/sync', SyncController::class)->name('get_sync');
Route::post('/api/v1/sync/ack', SyncController::class)->name('post_sync_ack');
Route::get('/api/v1/snapshots/{id}/catalog', SyncController::class)->name('get_snapshots_id_catalog');
Route::get('/api/v1/snapshots/{id}/revisions/{revision}', SyncController::class)->name('get_snapshots_id_revisions_revision');

Route::get('/api/v1/groups', NotesController::class)->name('get_groups');
Route::post('/api/v1/groups', NotesController::class)->name('post_groups');
Route::get('/api/v1/groups/{id}', NotesController::class)->name('get_groups_id');
Route::get('/api/v1/groups/{id}/threads', NotesController::class)->name('get_groups_id_threads');
Route::post('/api/v1/groups/{id}/threads', NotesController::class)->name('post_groups_id_threads');
Route::get('/api/v1/groups/{id}/trash', NotesController::class)->name('get_groups_id_trash');
Route::get('/api/v1/threads/{id}/entries', NotesController::class)->name('get_threads_id_entries');
Route::post('/api/v1/threads/{id}/entries', NotesController::class)->name('post_threads_id_entries');
Route::get('/api/v1/objects/{id}', NotesController::class)->name('get_objects_id');
Route::get('/api/v1/objects/{id}/revisions', NotesController::class)->name('get_objects_id_revisions');
Route::get('/api/v1/objects/{id}/revisions/{revision}', NotesController::class)->name('get_objects_id_revisions_revision');
Route::post('/api/v1/objects/{id}/revisions', NotesController::class)->name('post_objects_id_revisions');
Route::post('/api/v1/objects/{id}/tombstone', NotesController::class)->name('post_objects_id_tombstone');
Route::post('/api/v1/objects/{id}/restore', NotesController::class)->name('post_objects_id_restore');
Route::get('/api/v1/me/content-receipts/{id}', NotesController::class)->name('get_me_content_receipts_id');

// P10 closed signed membership, durable staging and history closure.
Route::get('/api/v1/me/group-invitations', GroupsController::class)->name('get_me_group_invitations');
Route::get('/api/v1/groups/{id}/journal', GroupsController::class)->name('get_groups_id_journal');
Route::post('/api/v1/groups/{id}/invites', GroupsController::class)->name('post_groups_id_invites');
Route::post('/api/v1/groups/{id}/accept', GroupsController::class)->name('post_groups_id_accept');
Route::post('/api/v1/groups/{id}/policy', GroupsController::class)->name('post_groups_id_policy');
Route::post('/api/v1/groups/{id}/owner-consent', GroupsController::class)->name('post_groups_id_owner_consent');
Route::post('/api/v1/groups/{id}/epoch/begin', GroupsController::class)->name('post_groups_id_epoch_begin');
Route::post('/api/v1/groups/{id}/epoch/page', GroupsController::class)->name('post_groups_id_epoch_page');
Route::post('/api/v1/groups/{id}/epoch/commit', GroupsController::class)->name('post_groups_id_epoch_commit');
Route::post('/api/v1/groups/{id}/history', GroupsController::class)->name('post_groups_id_history');
Route::post('/api/v1/groups/{id}/cancel', GroupsController::class)->name('post_groups_id_cancel');

Route::post('/api/v1/me/close-account', GroupsController::class)->name('post_me_close_account');

Route::get('/api/v1/me/group-receipts/{id}', GroupsController::class)->name('get_me_group_receipts_id');

// P12 bounded encrypted transfer and recovery; no direct blob URL.
Route::post('/api/v1/groups/{id}/uploads', FilesController::class)->name('post_groups_id_uploads');
Route::get('/api/v1/uploads/{id}', FilesController::class)->name('get_uploads_id');
Route::put('/api/v1/uploads/{id}/parts/{index}', FilesController::class)->name('put_uploads_id_parts_index');
Route::post('/api/v1/uploads/{id}/commit', FilesController::class)->name('post_uploads_id_commit');
Route::delete('/api/v1/uploads/{id}', FilesController::class)->name('delete_uploads_id');
Route::get('/api/v1/files/{version}/manifest', FilesController::class)->name('get_files_version_manifest');
Route::get('/api/v1/files/{version}/chunks/{index}', FilesController::class)->name('get_files_version_chunks_index');
Route::get('/api/v1/groups/{id}/files', FilesController::class)->name('get_groups_id_files');
Route::get('/api/v1/me/unattached-files', FilesController::class)->name('get_me_unattached_files');
Route::get('/api/v1/me/storage', FilesController::class)->name('get_me_storage');
Route::delete('/api/v1/files/{version}/unattached', FilesController::class)->name('delete_files_version_unattached');
Route::get('/api/v1/snapshots/{id}/files', SyncController::class)->name('get_snapshots_id_files');
