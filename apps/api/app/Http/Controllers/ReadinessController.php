<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\DB;
use Throwable;

final class ReadinessController
{
    public function __invoke(): JsonResponse
    {
        abort_unless(app()->environment(['local', 'testing']), 404);

        try {
            DB::select('SELECT 1');

            return response()->json(['status' => 'ready']);
        } catch (Throwable) {
            // No connection strings, queries or exception details in the response.
            return response()->json(['status' => 'unavailable'], 503);
        }
    }
}
