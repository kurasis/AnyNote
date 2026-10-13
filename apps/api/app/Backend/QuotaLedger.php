<?php

namespace App\Backend;

use App\Crypto\PublicProtocol as P;
use App\Http\ApiException;
use Illuminate\Support\Facades\DB;

/** Call inside the actor/group transaction, before the sync counter lock. */
final class QuotaLedger
{
    public function lock(string $account, string $group): array
    {
        if (DB::transactionLevel() < 1) {
            throw new \LogicException('Transaction required');
        }
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
        if (DB::transactionLevel() < 1) {
            throw new \LogicException('Transaction required');
        }
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
            DB::table('quota_movements')->insert(['id' => P::b64(random_bytes(16)), 'scope' => $row->scope, 'committed_delta' => $committed, 'reserved_delta' => $reserved]);
        }
    }

    /** Read/report first; correction is a separate explicit operator decision. */
    public function reconcile(bool $correct = false): array
    {
        return DB::transaction(function () use ($correct) {
            DB::table('quota_ledgers')->where('scope', 'global')->lockForUpdate()->first();
            $rows = DB::table('quota_ledgers')->orderBy('scope')->lockForUpdate()->get();
            $differences = [];
            foreach ($rows as $row) {
                $base = DB::table('quota_reconciliation_baselines')->where('scope', $row->scope)->first();
                $c = (int) ($base->committed_bytes ?? 0) + (int) DB::table('quota_movements')->where('scope', $row->scope)->sum('committed_delta');
                $r = (int) ($base->reserved_bytes ?? 0) + (int) DB::table('quota_movements')->where('scope', $row->scope)->sum('reserved_delta');
                if ($c !== (int) $row->committed_bytes || $r !== (int) $row->reserved_bytes) {
                    $differences[] = ['scope' => $row->scope, 'expected_committed_bytes' => (string) $c, 'expected_reserved_bytes' => (string) $r, 'observed_committed_bytes' => (string) $row->committed_bytes, 'observed_reserved_bytes' => (string) $row->reserved_bytes];
                    if ($correct) {
                        if ($c < 0 || $r < 0 || $c + $r > (int) $row->limit_bytes) {
                            throw new ApiException('INTEGRITY_FAILURE');
                        }
                        DB::table('quota_ledgers')->where('scope', $row->scope)->update(['committed_bytes' => $c, 'reserved_bytes' => $r]);
                    }
                }
            }

            return ['version' => 1, 'mode' => $correct ? 'explicit-correction' : 'report-only', 'differences' => $differences, 'pre_journal_baseline' => 'requires independent payload inventory for physical reconciliation'];
        }, 3);
    }
}
