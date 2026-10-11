<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Session\Middleware\StartSession;

/** Native credentials never create a browser cookie or require a browser session. */
final class AuthSession extends StartSession
{
    public function handle($request, Closure $next)
    {
        if (! $request->headers->has('Origin') && ! $request->headers->has('Cookie') && ($request->headers->has('Authorization') || $request->is('api/v1/auth/native/token') || $request->is('api/v1/auth/native/authorize'))) {
            return $next($request);
        }

        return parent::handle($request, $next);
    }
}
