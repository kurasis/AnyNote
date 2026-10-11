<?php

// Laravel's database session handler needs a defined metadata guard. Product authentication
// exclusively uses P06 passkey/session authority; no password/login/reset routes are registered.
return [
    'defaults' => ['guard' => 'web'],
    'guards' => ['web' => ['driver' => 'session', 'provider' => 'users']],
    'providers' => ['users' => ['driver' => 'database', 'table' => 'users']],
];
