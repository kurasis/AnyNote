<?php

namespace App\Backend;

use App\Http\ApiException;
use Illuminate\Support\Facades\DB;

/** Call inside the actor/group transaction, before the sync counter lock. */
final class QuotaLedger
{
    public function lock(string $account, string $group): array
    {
        $scopes = ['global', 'group/'.$group, 'account/'.$account];
        $rows = [DB::table('quota_ledgers')->where('scope', 'global')->lockForUpdate()->first()];
        foreach (array_slice($scopes, 1) as $scope) {
            DB::table('quota_ledgers')->insertOrIgnore(['scope' => $scope, 'limit_bytes' => 100000000000, 'pending_limit_bytes' => str_starts_with($scope, 'account/') ? 2147483648 : 5368709120]);
        }
        foreach (array_slice($scopes, 1) as $scope) {
            $rows[] = DB::table('quota_ledgers')->where('scope', $scope)->lockForUpdate()->first();
        }

        return $rows;
    }

    public function apply(array $ledgers, int $committed, int $reserved): void
    {
        foreach ($ledgers as $row) {
            $c = (int) $row->committed_bytes;
            $r = (int) $row->reserved_bytes;
            // Limits are <=100 GB; subtraction avoids overflow of hostile byte counts.
            if ($committed < -$c || $reserved < -$r || $committed > (int) $row->limit_bytes - $c || $reserved > (int) $row->pending_limit_bytes - $r || $c + $committed > (int) $row->limit_bytes - ($r + $reserved)) {
                throw new ApiException('QUOTA_EXCEEDED');
            }
        }
        foreach ($ledgers as $row) {
            DB::table('quota_ledgers')->where('scope', $row->scope)->update(['committed_bytes' => (int) $row->committed_bytes + $committed, 'reserved_bytes' => (int) $row->reserved_bytes + $reserved]);
        }
    }
}
