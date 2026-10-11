<?php

namespace Tests\Support;

use App\Crypto\PublicProtocol as P;
use Illuminate\Support\Facades\DB;

final class SyntheticBackend
{
    public static function seed(array $fixture): void
    {
        if (config('database.connections.mariadb.database') !== 'anynote_p04_tests' || ! app()->environment('testing') || $fixture['purpose'] !== 'PUBLIC_TEST_ONLY_NOT_PRODUCT_AUTHORIZATION') {
            throw new \LogicException('Owned testing database and PUBLIC corpus required');
        }
        foreach ($fixture['accounts'] as $index => $a) {
            DB::table('users')->insert(['id' => $a['account_id'], 'login_handle' => 'public-test-'.$index, 'status' => 'active']);
            DB::table('account_identities')->insert(['account_id' => $a['account_id'], 'root_fingerprint' => $a['root_fingerprint'], 'identity_record' => json_encode($a['identity']), 'recovery_generation' => 0, 'roster_sequence' => 0, 'roster_digest' => $a['roster_digest']]);
            DB::table('devices')->insert(['id' => $a['device_id'], 'account_id' => $a['account_id'], 'signing_key' => $a['certificate']['body']['device_signing_key'], 'encryption_key' => $a['certificate']['body']['device_encryption_key'], 'certificate_digest' => $a['certificate_digest'], 'certificate_record' => json_encode($a['certificate']), 'recovery_generation' => 0, 'status' => 'active', 'can_sign_content' => true]);
            DB::table('auth_sessions')->insert(['id' => P::b64(str_repeat(chr(80 + $index), 16)), 'account_id' => $a['account_id'], 'device_id' => $a['device_id'], 'secret_hash' => hash('sha256', $a['session_secret']), 'recovery_generation' => 0, 'state' => 'trusted', 'expires_at' => now()->addHour(), 'authenticated_at' => now()]);
        }
        foreach ($fixture['groups'] as $g) {
            DB::table('groups')->insert(['id' => $g['id'], 'owner_account_id' => $g['owner'], 'kind' => $g['kind'], 'state' => 'active', 'policy_sequence' => 0, 'policy_digest' => $g['policy_digest'], 'epoch_number' => 0, 'epoch_digest' => $g['epoch_digest']]);
            DB::table('group_memberships')->insert(['group_id' => $g['id'], 'account_id' => $g['owner'], 'role' => 'owner', 'status' => 'active', 'joined_policy' => 0]);
        }
        DB::table('group_memberships')->insert(['group_id' => $fixture['groups'][0]['id'], 'account_id' => $fixture['accounts'][1]['account_id'], 'role' => 'reader', 'status' => 'active', 'joined_policy' => 0]);
    }
}
