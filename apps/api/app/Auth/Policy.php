<?php

namespace App\Auth;

use App\Crypto\PublicProtocol as P;
use App\Http\ApiException;

final class Policy
{
    public static function origin(string $value): array
    {
        $p = parse_url($value);
        if (! is_array($p) || ($p['scheme'] ?? '') !== 'https' || ! isset($p['host']) || array_intersect(['user', 'pass', 'path', 'query', 'fragment'], array_keys($p)) || strtolower($p['host']) !== $p['host']) {
            throw new ApiException('TEMPORARY_UNAVAILABLE');
        }

        return $p;
    }

    public static function configured(): bool
    {
        try {
            self::check();

            return true;
        } catch (ApiException) {
            return false;
        }
    }

    public static function check(): void
    {
        $app = self::origin((string) config('api.app_origin'));
        $api = self::origin((string) config('passkeys.issuer'));
        if ($app['host'] === $api['host'] || config('passkeys.rp_id') !== $app['host'] || ! P::isBinary((string) config('api.service_id'), 16) || ! is_file((string) config('passkeys.private_key')) || ! is_file((string) config('passkeys.public_key'))) {
            throw new ApiException('TEMPORARY_UNAVAILABLE');
        }
        $private = openssl_pkey_get_private(file_get_contents(config('passkeys.private_key')));
        $public = openssl_pkey_get_public(file_get_contents(config('passkeys.public_key')));
        if ($private === false || $public === false) {
            throw new ApiException('TEMPORARY_UNAVAILABLE');
        }
        $a = openssl_pkey_get_details($private);
        $b = openssl_pkey_get_details($public);
        if ($a['type'] !== OPENSSL_KEYTYPE_RSA || $a['bits'] < 3072 || $a['key'] !== $b['key']) {
            throw new ApiException('TEMPORARY_UNAVAILABLE');
        }
    }

    public static function redirect(string $uri): void
    {
        $p = parse_url($uri);
        if (! is_array($p) || ($p['scheme'] ?? '') !== 'http' || ! in_array($p['host'] ?? '', ['127.0.0.1', '[::1]'], true) || ! isset($p['port'], $p['path']) || $p['port'] < 1 || $p['port'] > 65535 || ! preg_match('~^/callback/[A-Za-z0-9_-]{22}$~D', $p['path']) || array_intersect(['user', 'pass', 'query', 'fragment'], array_keys($p))) {
            throw new ApiException('INVALID_REQUEST');
        }
    }
}
