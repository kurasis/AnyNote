<?php

use App\Logging\SafeLogger;
use Monolog\Handler\NullHandler;

return [
    // Deployment cannot accidentally select a raw-message/exception logger via an env value.
    'default' => 'content_free',
    'deprecations' => ['channel' => 'content_free', 'trace' => false],
    'channels' => [
        'content_free' => ['driver' => 'custom', 'via' => SafeLogger::class],
        'null' => ['driver' => 'monolog', 'handler' => NullHandler::class],
        'emergency' => ['path' => '/dev/null'],
    ],
];
