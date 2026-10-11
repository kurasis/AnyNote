<?php

namespace App\Http\Middleware;

use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;

/** Retain Laravel token validation; Fetch Metadata never substitutes for the token. */
final class SessionCsrf extends PreventRequestForgery
{
    protected $addHttpCookie = false;

    protected function hasValidOrigin($request)
    {
        return false;
    }

    protected function inExceptArray($request)
    {
        if ($request->is('api/v1/auth/native/token') && ! $request->headers->has('Origin') && ! $request->headers->has('Cookie')) {
            return true;
        }
        if ($request->headers->has('Authorization') && ! $request->headers->has('Cookie') && ! $request->headers->has('Origin')) {
            return true;
        }

        return parent::inExceptArray($request);
    }

    protected function runningUnitTests()
    {
        return false;
    }
}
