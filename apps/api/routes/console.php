<?php

use App\Auth\Maintenance;
use App\Auth\Registration;
use App\Backend\AccountAdministration;
use App\Backend\QuotaLedger;
use App\Files\Service;
use App\Jobs\MaintenanceHeartbeat;
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
