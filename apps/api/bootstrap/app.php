<?php

use App\Http\ApiErrors;
use App\Http\Middleware\ApiBoundary;
use App\Http\Middleware\AuthSession;
use App\Http\Middleware\BoundedPostSize;
use App\Http\Middleware\SessionCsrf;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Http\Middleware\ValidatePostSize;
use Illuminate\Http\Request;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\View\Middleware\ShareErrorsFromSession;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(web: __DIR__.'/../routes/web.php', commands: __DIR__.'/../routes/console.php')
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->prepend(ApiBoundary::class);
        $middleware->replace(ValidatePostSize::class, BoundedPostSize::class);
        $middleware->web(remove: [ShareErrorsFromSession::class], replace: [PreventRequestForgery::class => SessionCsrf::class, StartSession::class => AuthSession::class]);
        $middleware->trustHosts(at: fn () => ['^'.preg_quote(parse_url((string) config('passkeys.issuer'), PHP_URL_HOST) ?: 'api.anynote.test', '/').'$'], subdomains: false);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(fn (Request $request) => true);
        $exceptions->render(fn (Throwable $exception, Request $request) => ApiErrors::fromThrowable($exception, $request));
        // The request boundary logs only typed status/route metadata. Suppress framework exception dumps.
        $exceptions->report(fn (Throwable $exception) => false);
    })->create();
