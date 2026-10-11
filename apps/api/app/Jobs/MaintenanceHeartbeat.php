<?php

namespace App\Jobs;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Support\Facades\DB;

final class MaintenanceHeartbeat implements ShouldQueue
{
    use Queueable;

    public int $tries = 3;

    public int $timeout = 10;

    public function handle(): void
    {
        DB::table('runtime_heartbeats')->updateOrInsert(['component' => 'queue'], ['observed_at' => now()]);
    }
}
