<?php

namespace App\Backend;

use App\Crypto\PublicProtocol as P;
use App\Http\ApiException;
use Illuminate\Support\Facades\DB;

/** Accounting foundation; P12 must add physical-space admission and byte durability. */
final class ReservationService
{
    public function __construct(private Authorization $authorization, private QuotaLedger $quota, private P $protocol) {}

    public function reserve(string $secret, string $bytes): array
    {
        $r = $this->protocol->decode('p04-api', 'quota-request', $bytes);

        return DB::transaction(function () use ($secret, $r) {
            $a = $this->authorization->actor($secret);
            $this->authorization->group($a, $r->group_id, 'write');
            $old = DB::table('quota_reservations')->where('id', $r->reservation_id)->lockForUpdate()->first();
            if ($old) {
                if ($old->account_id !== $a->accountId || $old->device_id !== $a->deviceId || $old->group_id !== $r->group_id) {
                    throw new ApiException('NOT_FOUND');
                }
                if ((string) $old->bytes !== $r->bytes) {
                    throw new ApiException('IDEMPOTENCY_MISMATCH');
                }
                if ($old->state !== 'reserved' || $old->expires_at <= now()->format('Y-m-d H:i:s')) {
                    throw new ApiException('UPLOAD_EXPIRED');
                }

                return ['reservation_id' => $old->id, 'state' => $old->state, 'bytes' => (string) $old->bytes];
            }
            $this->quota->apply($this->quota->lock($a->accountId, $r->group_id), 0, (int) $r->bytes);
            DB::table('quota_reservations')->insert(['id' => $r->reservation_id, 'account_id' => $a->accountId, 'device_id' => $a->deviceId, 'group_id' => $r->group_id, 'bytes' => (int) $r->bytes, 'state' => 'reserved', 'expires_at' => now()->addHours(24)]);

            return ['reservation_id' => $r->reservation_id, 'state' => 'reserved', 'bytes' => $r->bytes];
        }, 3);
    }

    /** Must be called from the future durable file-reference commit transaction. */
    public function convert(string $secret, string $group, string $reservation, int $actual): void
    {
        if (DB::transactionLevel() < 1) {
            throw new \LogicException('Transaction required');
        }
        $actor = $this->authorization->actor($secret);
        $this->authorization->group($actor, $group, 'write');
        $r = DB::table('quota_reservations')->where('id', $reservation)->lockForUpdate()->first();
        if (! $r || $r->account_id !== $actor->accountId || $r->device_id !== $actor->deviceId || $r->group_id !== $group) {
            throw new ApiException('NOT_FOUND');
        }
        if ($actual < 0 || $actual > (int) $r->bytes) {
            throw new ApiException('QUOTA_EXCEEDED');
        }
        if ($r->state === 'committed') {
            if ((int) $r->committed_bytes !== $actual) {
                throw new ApiException('IDEMPOTENCY_MISMATCH');
            }

            return;
        }
        if ($r->state !== 'reserved' || $r->expires_at <= now()->format('Y-m-d H:i:s')) {
            throw new ApiException('UPLOAD_EXPIRED');
        }
        $this->quota->apply($this->quota->lock($actor->accountId, $group), $actual, -(int) $r->bytes);
        DB::table('quota_reservations')->where('id', $r->id)->update(['state' => 'committed', 'committed_bytes' => $actual]);
    }

    public function cancel(string $secret, string $group, string $reservation): void
    {
        if (! P::isBinary($reservation, 16)) {
            throw new ApiException('NOT_FOUND');
        }
        DB::transaction(function () use ($secret, $group, $reservation) {
            $a = $this->authorization->actor($secret);
            $this->authorization->group($a, $group);
            $r = DB::table('quota_reservations')->where('id', $reservation)->lockForUpdate()->first();
            if (! $r || $r->account_id !== $a->accountId || $r->device_id !== $a->deviceId || $r->group_id !== $group) {
                throw new ApiException('NOT_FOUND');
            }
            if ($r->state === 'committed') {
                throw new ApiException('INVALID_REQUEST');
            }
            if ($r->state === 'released') {
                return;
            }
            $this->quota->apply($this->quota->lock($a->accountId, $group), 0, -(int) $r->bytes);
            DB::table('quota_reservations')->where('id', $r->id)->update(['state' => 'released']);
        }, 3);
    }
}
