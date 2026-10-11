<?php

use App\Backend\AccountAdministration;
use App\Jobs\MaintenanceHeartbeat;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schedule;

// No queue/scheduler jobs until their application contracts exist.

Artisan::command('accounts:bootstrap-admin {account}', function () {
    app(AccountAdministration::class)->bootstrap($this->argument('account'));
    $this->info('Administrative role initialized; group membership unchanged.');
});

Artisan::command('maintenance:heartbeat', function () {
    DB::table('runtime_heartbeats')->updateOrInsert(['component' => 'scheduler'], ['observed_at' => now()]);
    MaintenanceHeartbeat::dispatch();
});

Schedule::command('maintenance:heartbeat')->everyMinute();
