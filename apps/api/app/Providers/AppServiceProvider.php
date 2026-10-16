<?php

namespace App\Providers;

use App\Files\DirectoryDurability;
use Illuminate\Queue\Events\JobFailed;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Tests\Support\P14WindowsDurability;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        require_once app_path('Generated/Dtos.php');
        if (PHP_OS_FAMILY === 'Windows' && getenv('APP_ENV') === 'testing' && getenv('GITHUB_ACTIONS') === 'true') {
            $this->app->bind(DirectoryDurability::class, P14WindowsDurability::class);
        }
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        Event::listen(JobFailed::class, function (): void {
            // Aggregate operational state only; never persist raw job payloads or exceptions.
            DB::table('runtime_heartbeats')->updateOrInsert(['component' => 'queue-failure'], ['observed_at' => now()]);
        });
    }
}
