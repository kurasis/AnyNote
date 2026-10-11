<?php

namespace App\Contracts;

final class Catalogue
{
    public static function data(): array
    {
        static $catalogue;

        return $catalogue ??= json_decode(file_get_contents(__DIR__.'/../Generated/catalogue.json'), true, 32, JSON_THROW_ON_ERROR);
    }

    public static function error(string $code): array
    {
        foreach (self::data()['errors']['errors'] as $error) {
            if ($error['code'] === $code && ! $error['local_only']) {
                return $error;
            }
        }
        throw new \LogicException('Unknown transport error');
    }
}
