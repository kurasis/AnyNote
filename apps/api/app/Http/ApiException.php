<?php

namespace App\Http;

use App\Contracts\Catalogue;
use RuntimeException;

final class ApiException extends RuntimeException
{
    public function __construct(public readonly string $errorCode, public readonly array $details = [])
    {
        Catalogue::error($errorCode);
        parent::__construct($errorCode);
    }
}
