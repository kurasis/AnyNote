<?php

use App\Http\ApiException;
use App\Http\ControlJson;

// Offline raw parser differential harness. Does not bootstrap Laravel or connect SQL.
require __DIR__.'/../../vendor/autoload.php';

while (($line = fgets(STDIN, 8388608)) !== false) {
    $bytes = base64_decode(trim($line), true);
    if ($bytes === false) {
        exit(2);
    }
    try {
        ControlJson::decode($bytes);
        echo "1\n";
    } catch (ApiException $error) {
        if (! in_array($error->errorCode, ['INVALID_REQUEST', 'REQUEST_TOO_LARGE'], true)) {
            throw $error;
        }
        echo "0\n";
    }
}
