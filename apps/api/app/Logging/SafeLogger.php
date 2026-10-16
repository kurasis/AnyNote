<?php

namespace App\Logging;

use Monolog\Handler\RotatingFileHandler;
use Monolog\Logger;

final class SafeLogger
{
    public function __invoke(array $config): Logger
    {
        $handler = new RotatingFileHandler(storage_path('logs/content-free.jsonl'), 30, Logger::INFO, true, 0600, true);
        $handler->setFormatter(new ContentFreeFormatter);

        return new Logger('anynote', [$handler]);
    }
}
