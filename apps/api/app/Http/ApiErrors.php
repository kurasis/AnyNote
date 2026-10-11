<?php

namespace App\Http;

use App\Contracts\Catalogue;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Session\TokenMismatchException;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Throwable;

final class ApiErrors
{
    public static function requestId(Request $request): string
    {
        $id = $request->attributes->get('anynote_request_id');
        if (! is_string($id)) {
            $id = rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '=');
            $request->attributes->set('anynote_request_id', $id);
        }

        return $id;
    }

    public static function fromThrowable(Throwable $exception, Request $request): JsonResponse
    {
        $code = match (true) {
            $exception instanceof ApiException => $exception->errorCode,
            $exception instanceof TokenMismatchException => 'INVALID_REQUEST',
            $exception instanceof AuthenticationException => 'AUTH_REQUIRED',
            $exception instanceof AuthorizationException => 'NOT_FOUND',
            $exception instanceof HttpExceptionInterface && in_array($exception->getStatusCode(), [403, 404, 405], true) => 'NOT_FOUND',
            $exception instanceof HttpExceptionInterface && $exception->getStatusCode() === 413 => 'REQUEST_TOO_LARGE',
            $exception instanceof HttpExceptionInterface && $exception->getStatusCode() === 429 => 'RATE_LIMITED',
            $exception instanceof HttpExceptionInterface && $exception->getStatusCode() < 500 => 'INVALID_REQUEST',
            default => 'TEMPORARY_UNAVAILABLE',
        };

        return self::response($request, $code, $exception instanceof ApiException ? $exception->details : []);
    }

    public static function response(Request $request, string $code, array $details = []): JsonResponse
    {
        $definition = Catalogue::error($code);
        $safe = [];
        // Details are trusted application values, never exception/request strings.
        foreach (array_slice($details, 0, 32) as $detail) {
            if (! is_array($detail) || array_keys($detail) !== ['key', 'value'] || ! is_string($detail['value'])) {
                continue;
            }
            $valid = match ($detail['key']) {
                'expected_head', 'current_head' => (bool) preg_match('/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/D', $detail['value']),
                'required_bytes', 'available_bytes' => (bool) preg_match('/^(0|[1-9][0-9]{0,18})$/D', $detail['value']) && strlen($detail['value']) <= 19 && strcmp(str_pad($detail['value'], 19, '0', STR_PAD_LEFT), '9223372036854775807') <= 0,
                'retry_after_ms' => $definition['retryable'] && ctype_digit($detail['value']) && (int) $detail['value'] >= 1000 && (int) $detail['value'] <= 60000,
                default => false,
            };
            if ($valid && $code !== 'NOT_FOUND' && $code !== 'ACCESS_REVOKED') {
                $safe[] = $detail;
            }
        }
        $response = response()->json(['error' => [
            'code' => $definition['code'], 'message_key' => $definition['message_key'],
            'request_id' => self::requestId($request), 'retryable' => $definition['retryable'], 'details' => $safe,
        ]], $definition['http_status']);
        if ($definition['retryable']) {
            $milliseconds = 1000;
            foreach ($safe as $detail) {
                if ($detail['key'] === 'retry_after_ms') {
                    $milliseconds = (int) $detail['value'];
                }
            }
            $response->headers->set('Retry-After', (string) (int) ceil($milliseconds / 1000));
        }

        return $response;
    }
}
