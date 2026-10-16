<?php

return [
    'accel' => (bool) env('ANYNOTE_ACCEL_DELIVERY', false),
    // Kept outside SQL so an old database cannot remove the restore fence.
    'recovery_fence' => storage_path('app/private/RESTORE_QUARANTINE'),
    'reserve_bytes' => in_array(env('APP_ENV'), ['local', 'testing'], true) ? 268435456 : 10737418240,
    'reserve_fraction' => in_array(env('APP_ENV'), ['local', 'testing'], true) ? 0.0 : 0.1,
];
