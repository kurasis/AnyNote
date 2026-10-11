<?php

namespace App\Http;

use JsonException;
use stdClass;

final class ControlJson
{
    private static function finite(mixed $value): void
    {
        if (is_float($value) && ! is_finite($value)) {
            throw new ApiException('INVALID_REQUEST');
        }
        if (is_array($value) || is_object($value)) {
            foreach ($value as $child) {
                self::finite($child);
            }
        }
    }

    public static function decode(string $bytes): stdClass
    {
        if (strlen($bytes) > 4194304) {
            throw new ApiException('REQUEST_TOO_LARGE');
        }
        try {
            $value = json_decode($bytes, false, 33, JSON_THROW_ON_ERROR);
            if (! $value instanceof stdClass) {
                throw new ApiException('INVALID_REQUEST');
            }
            self::finite($value);
            // Native JSON validates syntax/UTF-8/escapes. Token walking preserves raw duplicate keys.
            $frames = [];
            $length = strlen($bytes);
            for ($i = 0; $i < $length; $i++) {
                $char = $bytes[$i];
                if ($char === '{' || $char === '[') {
                    if (count($frames) >= 32) {
                        throw new ApiException('INVALID_REQUEST');
                    }
                    $frames[] = ['object' => $char === '{', 'key' => $char === '{', 'seen' => []];
                } elseif ($char === '}' || $char === ']') {
                    array_pop($frames);
                } elseif ($char === ',' && $frames !== []) {
                    $frames[count($frames) - 1]['key'] = $frames[count($frames) - 1]['object'];
                } elseif ($char === '"') {
                    $start = $i++;
                    for (; $i < $length; $i++) {
                        if ($bytes[$i] === '\\') {
                            $i++;
                        } elseif ($bytes[$i] === '"') {
                            break;
                        }
                    }
                    $index = count($frames) - 1;
                    if ($index >= 0 && $frames[$index]['object'] && $frames[$index]['key']) {
                        $name = json_decode(substr($bytes, $start, $i - $start + 1), false, 2, JSON_THROW_ON_ERROR);
                        if (isset($frames[$index]['seen'][$name])) {
                            throw new ApiException('INVALID_REQUEST');
                        }
                        $frames[$index]['seen'][$name] = true;
                        $frames[$index]['key'] = false;
                    }
                }
            }

            return $value;
        } catch (JsonException) {
            throw new ApiException('INVALID_REQUEST');
        }
    }
}
