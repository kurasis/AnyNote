<?php

namespace App\Backend;

use App\Crypto\PublicProtocol as P;
use App\Http\ApiException;
use Illuminate\Support\Facades\DB;

final class AccountAdministration
{
    public function __construct(private Authorization $authorization, private P $protocol) {}

    public function invite(string $secret, string $bytes): array
    {
        $r = $this->protocol->decode('p04-api', 'invite-request', $bytes);

        return DB::transaction(function () use ($secret, $r) {
            $a = $this->authorization->actor($secret);
            if (! $a->admin || ! $a->recent) {
                throw new ApiException('ROLE_FORBIDDEN');
            }
            if (DB::table('account_invites')->where('creator_id', $a->accountId)->where('status', 'pending')->where('expires_at', '>', now())->count() >= 20) {
                throw new ApiException('RESOURCE_LIMIT');
            }
            $token = P::b64(random_bytes(32));
            $id = P::b64(random_bytes(16));
            DB::table('account_invites')->insert(['id' => $id, 'creator_id' => $a->accountId, 'token_hash' => hash('sha256', $token), 'recipient_binding_hash' => $r->recipient_binding_hash, 'status' => 'pending', 'expires_at' => now()->addHours($r->valid_hours)]);

            return ['invitation_id' => $id, 'token' => $token];
        }, 3);
    }

    /** Console-only promotion of an existing identity; never creates a content owner. */
    public function bootstrap(string $account): void
    {
        if (! app()->runningInConsole() || ! P::isBinary($account, 16)) {
            throw new ApiException('INVALID_REQUEST');
        }
        DB::transaction(function () use ($account) {
            // One administrative coordination row serializes the initial bootstrap.
            DB::table('operator_coordination')->where('singleton', 1)->lockForUpdate()->first();
            if (DB::table('users')->where('is_admin', true)->exists()) {
                throw new ApiException('INVALID_REQUEST');
            }
            if (! DB::table('users')->where('id', $account)->where('status', 'active')->exists() || ! DB::table('account_identities')->where('account_id', $account)->exists()) {
                throw new ApiException('NOT_FOUND');
            }
            DB::table('users')->where('id', $account)->update(['is_admin' => true]);
        });
    }
}
