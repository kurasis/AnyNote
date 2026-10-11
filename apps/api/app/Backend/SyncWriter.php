<?php

namespace App\Backend;

use App\Crypto\PublicProtocol as P;
use App\Http\ApiException;
use Illuminate\Support\Facades\DB;

final class SyncWriter
{
    /** LAST lock. No external I/O or further business locks after this call. */
    public function append(array $events): array
    {
        if ($events === [] || count($events) > 100) {
            throw new ApiException('RESOURCE_LIMIT');
        }
        $counter = DB::table('sync_counters')->where('id', 1)->lockForUpdate()->first();
        if (! $counter || ! P::counter((string) $counter->sequence) || (int) $counter->sequence > PHP_INT_MAX - count($events)) {
            throw new ApiException('RESOURCE_LIMIT');
        }
        $sequence = (int) $counter->sequence;
        foreach ($events as $event) {
            DB::table('sync_events')->insert(['sequence' => ++$sequence, 'event_id' => P::b64(random_bytes(16)), ...$event]);
        }
        DB::table('sync_counters')->where('id', 1)->update(['sequence' => $sequence]);

        return ['generation' => $counter->generation, 'sequence' => (string) $sequence];
    }
}
