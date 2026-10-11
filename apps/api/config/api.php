<?php

return [
    'service_id' => env('ANYNOTE_SERVICE_ID', in_array(env('APP_ENV'), ['local', 'testing'], true) ? 'AAAAAAAAAAAAAAAAAAAAAQ' : null),
    'app_origin' => env('ANYNOTE_APP_ORIGIN', in_array(env('APP_ENV'), ['local', 'testing'], true) ? 'http://app.anynote.test:18080' : null),
];
