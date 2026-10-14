<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        require_once app_path('Generated/Dtos.php');
        if (PHP_OS_FAMILY === 'Windows' && getenv('APP_ENV') === 'testing' && getenv('GITHUB_ACTIONS') === 'true') {
            $this->app->bind(\App\Files\DirectoryDurability::class, \Tests\Support\P14WindowsDurability::class);
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
