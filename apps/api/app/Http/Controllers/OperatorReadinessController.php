<?php

namespace App\Http\Controllers;

use App\Backend\Authorization;
use App\Http\ApiException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

final class OperatorReadinessController
{
    public function __invoke(Request $request, Authorization $authorization): JsonResponse
    {
        return DB::transaction(function () use ($request, $authorization) {
            $actor = $authorization->actor($request->bearerToken() ?? '');
            if (! $actor->admin || ! $actor->recent) {
                throw new ApiException('NOT_FOUND');
            }
            $database = DB::selectOne('SELECT @@innodb_flush_log_at_trx_commit AS durable');
            if ((int) $database->durable !== 1 || ! DB::table('sync_counters')->where('id', 1)->exists()) {
                throw new ApiException('TEMPORARY_UNAVAILABLE');
            }
            foreach (['queue', 'scheduler'] as $component) {
                if (! DB::table('runtime_heartbeats')->where('component', $component)->where('observed_at', '>', now()->subSeconds(150))->exists()) {
                    throw new ApiException('TEMPORARY_UNAVAILABLE');
                }
            }

            return response()->json(['status' => 'ready', 'database' => 'ready', 'queue' => 'ready', 'scheduler' => 'ready']);
        }, 3);
    }
}
