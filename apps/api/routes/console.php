<?php

use App\Auth\Maintenance;
use App\Auth\Registration;
use App\Backend\AccountAdministration;
use App\Backend\QuotaLedger;
use App\Content\Retainer;
use App\Files\Service;
use App\Jobs\MaintenanceHeartbeat;
use App\Operations\Delivery;
use App\Operations\Recovery;
use App\Operations\RecoveryFence;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schedule;

// No queue/scheduler jobs until their application contracts exist.

Artisan::command('accounts:bootstrap-invite {--hours=48}', function () {
    $this->line(app(Registration::class)->bootstrap((int) $this->option('hours')));
})->purpose('Create one expiring bootstrap invitation; secret is printed once to the operator console.');

Artisan::command('accounts:bootstrap-admin {account}', function () {
    app(AccountAdministration::class)->bootstrap($this->argument('account'));
    $this->info('Administrative role initialized; group membership unchanged.');
});

Artisan::command('maintenance:heartbeat', function () {
    DB::table('runtime_heartbeats')->updateOrInsert(['component' => 'scheduler'], ['observed_at' => now()]);
    MaintenanceHeartbeat::dispatch();
});

Schedule::command('maintenance:heartbeat')->everyMinute();

Artisan::command('auth:prune', function () {
    $this->info('Expired authentication rows removed: '.app(Maintenance::class)->prune());
});
Schedule::command('auth:prune')->everyMinute();

Artisan::command('files:collect', function (Service $files) {
    $this->line(json_encode($files->collect(), JSON_THROW_ON_ERROR));
})->purpose('Collect only expired staging and eligible unattached ciphertext');
Artisan::command('files:reconcile {--correct}', function (QuotaLedger $ledger) {
    $this->line(json_encode($ledger->reconcile((bool) $this->option('correct')), JSON_THROW_ON_ERROR));
})->purpose('Report quota journal differences; correction requires an explicit operator flag');

Artisan::command('content:retain {group} {--after=} {--limit=100} {--apply}', function (Retainer $retainer) {
    $this->line(json_encode($retainer->run($this->argument('group'), (int) $this->option('limit'), (bool) $this->option('apply'), $this->option('after') ?: null), JSON_THROW_ON_ERROR));
})->purpose('Report reference-safe retention; explicit apply compacts eligible payloads while preserving signed ancestry');

Artisan::command('operations:inventory', function (Recovery $recovery) {
    $this->line(json_encode($recovery->inventory(), JSON_THROW_ON_ERROR));
})->purpose('Reconcile immutable ciphertext references; requires a quiescent service');
Artisan::command('operations:quarantine', function (Recovery $recovery) {
    $this->line(json_encode($recovery->quarantine(), JSON_THROW_ON_ERROR));
})->purpose('Invalidate restored sessions and establish a fresh generation behind the persistent host fence');
Artisan::command('operations:catalogue {group}', function (Recovery $recovery) {
    $this->line(json_encode($recovery->catalogue($this->argument('group')), JSON_THROW_ON_ERROR));
})->purpose('Export bounded ciphertext-only private-genesis recovery metadata; never removes quarantine');
Artisan::command('operations:maintain', function () {
    app(RecoveryFence::class)->admit();
    $locked = DB::selectOne("SELECT GET_LOCK('anynote-maintenance', 0) AS acquired");
    if ((int) $locked->acquired !== 1) {
        $this->line('{"status":"BUSY"}');

        return;
    }
    try {
        $auth = app(Maintenance::class)->prune();
        $files = app(Service::class)->collect(50);
        $deliveries = app(Delivery::class)->collect();
        $expiredGrants = app(App\Operations\Maintenance::class)->security();
        $invites = DB::table('account_invites')->where('status', 'pending')->where('expires_at', '<=', now())->limit(100)->update(['status' => 'cancelled']);
        $enrollments = DB::table('enrollment_sessions')->whereIn('state', ['pending', 'approved'])->where('expires_at', '<=', now())->limit(100)->update(['state' => 'expired']);
        $this->line(json_encode(['status' => 'PASS', 'authentication_rows' => $auth, 'files' => $files, 'invitations' => $invites, 'enrollments' => $enrollments, 'delivery_leases' => $deliveries, 'expired_unpublished_grant_pages' => $expiredGrants], JSON_THROW_ON_ERROR));
    } finally {
        DB::select("SELECT RELEASE_LOCK('anynote-maintenance')");
    }
})->purpose('Bounded, reference-safe maintenance under a cross-process database lock');
Schedule::command('operations:maintain')->everyMinute();

Artisan::command('operations:security', function () {
    $this->line(json_encode(['version' => 1, 'created_at' => gmdate('c'), 'service_id' => config('api.service_id'),
        'users' => DB::table('users')->orderBy('id')->get(['id', 'status'])->all(),
        'rosters' => DB::table('account_identities')->orderBy('account_id')->get(['account_id', 'root_fingerprint', 'recovery_generation', 'roster_sequence', 'roster_digest'])->all(),
        'devices' => DB::table('devices')->orderBy('id')->get(['id', 'account_id', 'status', 'certificate_digest'])->all(),
        'passkeys' => DB::table('passkey_credentials')->orderBy('id')->get(['id', 'account_id', 'credential_digest'])->all(),
        'groups' => DB::table('groups')->orderBy('id')->get(['id', 'policy_sequence', 'policy_digest', 'epoch_number', 'epoch_digest', 'history_checkpoint_digest'])->all(),
    ], JSON_THROW_ON_ERROR));
})->purpose('Restricted public-security checkpoint for independently signed off-host custody; contains sensitive metadata');

Artisan::command('operations:health', function () {
    $disk = disk_free_space(storage_path('app/private'));
    $total = disk_total_space(storage_path('app/private'));
    $components = ['database' => (int) DB::selectOne('SELECT @@innodb_flush_log_at_trx_commit AS durable')->durable === 1];
    foreach (['queue', 'scheduler'] as $component) {
        $components[$component] = DB::table('runtime_heartbeats')->where('component', $component)->where('observed_at', '>', now()->subSeconds(150))->exists();
    }
    $recentFailure = DB::table('runtime_heartbeats')->where('component', 'queue-failure')->where('observed_at', '>', now()->subMinutes(15))->exists();
    $ready = ! $recentFailure && ! app(RecoveryFence::class)->active() && ! in_array(false, $components, true) && $disk !== false && $total !== false && $disk > max(10737418240, (int) ceil($total * 0.1));
    $this->line(json_encode(['status' => $ready ? 'ready' : 'unavailable', 'components' => $components, 'recent_queue_failure' => $recentFailure, 'delivery_leases' => DB::table('ciphertext_delivery_leases')->count(), 'queue_depth' => DB::table('jobs')->count(), 'free_bytes' => $disk, 'total_bytes' => $total, 'restore_quarantine' => app(RecoveryFence::class)->active()], JSON_THROW_ON_ERROR));

    return $ready ? 0 : 1;
})->purpose('Private operator health metrics; no public identifiers or content labels');
