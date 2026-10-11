<?php

namespace App\Auth;

use App\Http\ApiException;
use Illuminate\Support\Facades\DB;

final class RateLimits
{
    /** Commit rate admission separately: an invalid ceremony must still count. */
    public function hit(string $purpose, string $binding, int $maximum = 20, int $seconds = 60): void
    {
        $id = hash_hmac('sha256', 'AnyNote/P06/rate/'.$purpose."\0".$binding, (string) config('app.key'));
        $limited = DB::transaction(function () use ($id, $maximum, $seconds) {
            // Read the current bucket under an exclusive lock before mutation; a
            // nonlocking snapshot followed by duplicate-key upsert can raise MariaDB
            // ER_CHECKREAD (1020). Missing-row insertion may deadlock with another
            // first admission; Laravel rolls back and retries this bounded transaction.
            $row = DB::table('auth_rate_buckets')->where('id', $id)->lockForUpdate()->first();
            if ($row === null) {
                if (DB::table('auth_rate_buckets')->count() >= 50000) {
                    return true;
                }
                DB::table('auth_rate_buckets')->insert(['id' => $id, 'attempts' => 0, 'expires_at' => now()->addSeconds($seconds)]);
                $row = DB::table('auth_rate_buckets')->where('id', $id)->lockForUpdate()->first();
            }
            if ($row->expires_at <= now()->format('Y-m-d H:i:s')) {
                DB::table('auth_rate_buckets')->where('id', $id)->update(['attempts' => 0, 'expires_at' => now()->addSeconds($seconds)]);
                $row->attempts = 0;
            }
            if ($row->attempts >= $maximum) {
                return true;
            }
            DB::table('auth_rate_buckets')->where('id', $id)->increment('attempts');

            return false;
        }, 8);
        if ($limited) {
            throw new ApiException('RATE_LIMITED', [['key' => 'retry_after_ms', 'value' => (string) min(60000, $seconds * 1000)]]);
        }
    }
}
