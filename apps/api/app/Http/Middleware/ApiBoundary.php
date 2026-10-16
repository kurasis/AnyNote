<?php

namespace App\Http\Middleware;

use App\Http\ApiErrors;
use App\Http\ApiException;
use App\Http\ControlJson;
use App\Operations\RecoveryFence;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

final class ApiBoundary
{
    public function handle(Request $request, Closure $next): Response
    {
        $started = hrtime(true);
        $id = ApiErrors::requestId($request);
        $origin = $request->headers->get('Origin');
        $allowed = config('api.app_origin');
        $originParts = is_string($allowed) ? parse_url($allowed) : false;
        $originConfigured = is_array($originParts) && isset($originParts['scheme'], $originParts['host']) && ! array_intersect(['user', 'pass', 'path', 'query', 'fragment'], array_keys($originParts)) && ($originParts['scheme'] === 'https' || (app()->environment(['local', 'testing']) && $originParts['scheme'] === 'http'));
        $cors = $originConfigured && is_string($origin) && is_string($allowed) && $origin === $allowed;
        try {
            if ($request->server->get('ANYNOTE_EDGE_ERROR') === 'request-too-large') {
                throw new ApiException('REQUEST_TOO_LARGE');
            }
            if ($request->is('api/*')) {
                app(RecoveryFence::class)->admit();
                if (! app()->environment(['local', 'testing']) && ! $request->isSecure()) {
                    throw new ApiException('INVALID_REQUEST');
                }
                if ($origin !== null && ! $cors) {
                    throw new ApiException('NOT_FOUND');
                }
                $profile = $request->headers->get('X-AnyNote-Profile');
                if ($profile !== null && $profile !== 'p02-v1') {
                    throw new ApiException('UNSUPPORTED_SCHEMA');
                }
                if ($request->isMethod('OPTIONS')) {
                    $headers = strtolower($request->headers->get('Access-Control-Request-Headers', ''));
                    $requested = array_filter(array_map('trim', explode(',', $headers)));
                    if (! $cors || ! in_array($request->headers->get('Access-Control-Request-Method'), ['GET', 'POST', 'PUT', 'DELETE'], true) || array_diff($requested, ['content-type', 'x-anynote-profile', 'x-csrf-token', 'authorization'])) {
                        throw new ApiException('NOT_FOUND');
                    }
                    $response = new Response('', 204);
                } else {
                    $binaryPart = $request->isMethod('PUT') && preg_match('#^api/v1/uploads/[A-Za-z0-9_-]{22}/parts/(0|[1-9][0-9]{0,2})$#D', $request->path());
                    if ($binaryPart) {
                        if ($request->header('Content-Type') !== 'application/octet-stream' || (int) $request->header('Content-Length', '0') > 8388624) {
                            throw new ApiException('INVALID_REQUEST');
                        }
                        // Symfony/PHP returns a stream; do not materialize binary input in JSON.
                        $body = '';
                    } else {
                        $body = $request->getContent();
                    }
                    if (! $binaryPart && (strlen($body) > 4194304 || (int) $request->headers->get('Content-Length', '0') > 4194304)) {
                        throw new ApiException('REQUEST_TOO_LARGE');
                    }
                    if ($body !== '') {
                        if (strtolower(explode(';', $request->headers->get('Content-Type', ''))[0]) !== 'application/json') {
                            throw new ApiException('INVALID_REQUEST');
                        }
                        $request->attributes->set('anynote_control', ControlJson::decode($body));
                    }
                    $response = $next($request);
                }
            } else {
                $response = $next($request);
            }
        } catch (Throwable $exception) {
            $response = ApiErrors::fromThrowable($exception, $request);
        }
        $response->headers->set('X-Request-ID', $id);
        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->setVary(array_unique([...$response->getVary(), 'Origin']));
        if ($cors) {
            $response->headers->set('Access-Control-Allow-Origin', $allowed);
            $response->headers->set('Access-Control-Allow-Credentials', 'true');
            $response->headers->set('Access-Control-Expose-Headers', 'X-Request-ID, Retry-After');
            if ($request->isMethod('OPTIONS')) {
                $response->headers->set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
                $response->headers->set('Access-Control-Allow-Headers', 'Content-Type, X-AnyNote-Profile, X-CSRF-Token, Authorization');
                $response->headers->set('Access-Control-Max-Age', '300');
            }
        }
        $code = $response instanceof JsonResponse ? ($response->getData(true)['error']['code'] ?? null) : null;
        Log::info($response->getStatusCode() >= 400 ? 'api.error' : 'api.request', ['code' => $code, 'request_id' => $id, 'status' => $response->getStatusCode(), 'method' => $request->method(), 'route_id' => $request->route()?->getName(), 'elapsed_ms' => min(60000, (int) ((hrtime(true) - $started) / 1000000))]);

        return $response;
    }
}
