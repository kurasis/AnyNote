<?php

namespace App\Providers;

use App\Files\DirectoryDurability;
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
        //
    }
}
