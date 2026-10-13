<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Exceptions\PostTooLargeException;
use Illuminate\Http\Middleware\ValidatePostSize;

/** Preserve Laravel's control limit; narrowly allow one authenticated AEAD part. */
final class BoundedPostSize extends ValidatePostSize
{
    public function handle($request, Closure $next)
    {
        if ($request->isMethod('PUT') && preg_match('#^api/v1/uploads/[A-Za-z0-9_-]{22}/parts/(0|[1-9][0-9]{0,2})$#D', $request->path()) && $request->header('Content-Type') === 'application/octet-stream') {
            if ((int) $request->server('CONTENT_LENGTH', 0) > 8388624) {
                throw new PostTooLargeException;
            }

            return $next($request);
        }

        return parent::handle($request, $next);
    }
}
