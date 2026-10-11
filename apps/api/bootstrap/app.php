<?php

use App\Http\ApiErrors;
use App\Http\Middleware\ApiBoundary;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(web: __DIR__.'/../routes/web.php', commands: __DIR__.'/../routes/console.php')
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->prepend(ApiBoundary::class);
        $middleware->trustHosts(at: ['^api\\.anynote\\.test$'], subdomains: false);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(fn (Request $request) => true);
        $exceptions->render(fn (Throwable $exception, Request $request) => ApiErrors::fromThrowable($exception, $request));
        // The request boundary logs only typed status/route metadata. Suppress framework exception dumps.
        $exceptions->report(fn (Throwable $exception) => false);
    })->create();
