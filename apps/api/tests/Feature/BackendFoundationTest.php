<?php

namespace Tests\Feature;

use App\Backend\AccountAdministration;
use App\Backend\Authorization;
use App\Backend\ObjectService;
use App\Backend\ReservationService;
use App\Backend\ScopedRepository;
use App\Crypto\PublicProtocol as P;
use App\Http\ApiException;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\Group;
use Tests\Support\SyntheticBackend;
use Tests\TestCase;

#[Group('backend')]
final class BackendFoundationTest extends TestCase
{
    private array $fixture;

    protected function setUp(): void
    {
        parent::setUp();
        $this->assertTrue(app()->environment(['local', 'testing']));
        $this->app['env'] = 'testing';
        $this->assertSame('anynote_p04_tests', config('database.connections.mariadb.database'));
        Artisan::call('migrate', ['--no-interaction' => true]);
        if ($this->name() === 'test_sql_fault_after_counter_allocation_rolls_back_every_effect') {
            $operation = P::b64(str_repeat(chr(62), 16));
            DB::unprepared("CREATE TRIGGER p04_test_receipt_failure BEFORE INSERT ON mutation_receipts FOR EACH ROW BEGIN IF NEW.operation_id='".$operation."' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Synthetic fault'; END IF; END");
        }
        DB::beginTransaction();
        $this->fixture = json_decode(file_get_contents(storage_path('framework/testing/p04-fixtures.json')), true, 32, JSON_THROW_ON_ERROR);
        config(['api.service_id' => $this->fixture['service_id']]);
        SyntheticBackend::seed($this->fixture);
    }

    protected function tearDown(): void
    {
        while (DB::transactionLevel() > 0) {
            DB::rollBack();
        }
        if ($this->name() === 'test_sql_fault_after_counter_allocation_rolls_back_every_effect') {
            DB::unprepared('DROP TRIGGER p04_test_receipt_failure');
        }
        parent::tearDown();
    }

    private function secret(int $index = 0): string
    {
        return $this->fixture['accounts'][$index]['session_secret'];
    }

    private function group(int $index = 0): string
    {
        return $this->fixture['groups'][$index]['id'];
    }

    private function request(): array
    {
        return $this->fixture['request'];
    }

    private function commit(?array $r = null, int $index = 0): array
    {
        return app(ObjectService::class)->commit($this->secret($index), json_encode($r ?? $this->request(), JSON_THROW_ON_ERROR));
    }

    private function denied(string $code, callable $call): void
    {
        try {
            $call();
            $this->fail('Expected rejection '.$code);
        } catch (ApiException $e) {
            $this->assertSame($code, $e->errorCode);
        }
    }

    private function signed(array $r, int $index = 0): array
    {
        $h = &$r['bundle']['envelope']['header'];
        $r['group_id'] = $h['context']['group_id'];
        $r['object_id'] = $h['context']['object_id'];
        $r['object_kind'] = $h['context']['object_kind'];
        $r['thread_id'] = $h['context']['thread_id'];
        $r['action'] = $h['context']['action'];
        $r['bundle']['wrap']['context'] = $h['context'];
        $h['key_wrap_digest'] = P::digest('p02-v1', 'wrap', json_decode(json_encode($r['bundle']['wrap'])));
        $key = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair(str_repeat(chr(1 + $index), 32)));
        $r['bundle']['envelope']['signature'] = P::b64(sodium_crypto_sign_detached("AnyNote/p02-v1/sign/object-revision\0".P::canonical(json_decode(json_encode($h))), $key));

        return $r;
    }

    public function test_real_node_ciphertext_signature_and_atomic_receipt_commit(): void
    {
        $b = app(P::class)->bundle(json_encode($this->request()['bundle']), $this->fixture['accounts'][0]['certificate']['body']['device_signing_key']);
        $this->assertSame($this->fixture['canonical_header'], P::canonical($b->envelope->header));
        $this->assertSame($this->fixture['expected_bundle_digest'], P::digest('p02-v1', 'bundle', $b));
        $before = DB::table('sync_counters')->value('sequence');
        $result = $this->commit();
        $this->assertSame((string) ($before + 1), $result['receipt']['cursor']['sequence']);
        app(P::class)->decode('p04-api', 'commit-result', json_encode($result));
        $this->assertSame(1, DB::table('object_revisions')->count());
        $this->assertSame(1, DB::table('object_key_wraps')->count());
        $this->assertSame(1, DB::table('object_heads')->count());
        $this->assertSame(1, DB::table('mutation_receipts')->count());
        $this->assertSame($result, $this->commit());
        $this->assertSame($result, app(ScopedRepository::class)->receipt($this->secret(), $this->request()['bundle']['envelope']['header']['context']['operation_id']));
        $this->assertSame(1, DB::table('sync_events')->count());
        $expected = strlen(P::binary($this->request()['bundle']['ciphertext'])) + 48;
        foreach (DB::table('quota_ledgers')->where('scope', '!=', 'security')->get() as $row) {
            $this->assertSame($expected, (int) $row->committed_bytes);
        }
        $this->assertSame(0, (int) DB::table('quota_ledgers')->where('scope', 'security')->value('committed_bytes'));
    }

    public function test_three_accounts_cross_group_scope_reader_and_admin_do_not_gain_write_authority(): void
    {
        $this->denied('NOT_FOUND', fn () => $this->commit(null, 2));
        DB::table('users')->where('id', $this->fixture['accounts'][2]['account_id'])->update(['is_admin' => true]);
        $this->denied('NOT_FOUND', fn () => $this->commit(null, 2));
        $r = $this->request();
        $r['bundle']['envelope']['header']['context']['author'] = ['account_id' => $this->fixture['accounts'][1]['account_id'], 'device_id' => $this->fixture['accounts'][1]['device_id'], 'root_fingerprint' => $this->fixture['accounts'][1]['root_fingerprint'], 'recovery_generation' => '0', 'roster' => ['version' => '0', 'digest' => $this->fixture['accounts'][1]['roster_digest']]];
        $this->denied('ROLE_FORBIDDEN', fn () => $this->commit($this->signed($r, 1), 1));
        $r = $this->request();
        $r['group_id'] = $this->group(1);
        $this->denied('NOT_FOUND', fn () => $this->commit($r));
        $this->assertSame(0, DB::table('object_revisions')->count());
        $this->commit();
        $object = $this->request()['object_id'];
        $this->assertCount(1, app(ScopedRepository::class)->revisions($this->secret(1), $this->group(), $object));
        $this->denied('NOT_FOUND', fn () => app(ScopedRepository::class)->revisions($this->secret(2), $this->group(), $object));
        $this->denied('NOT_FOUND', fn () => app(ScopedRepository::class)->revisions($this->secret(2), $this->group(1), $object));
    }

    public function test_raw_schema_signature_and_observed_byte_rejections(): void
    {
        foreach ([fn (&$r) => $r['extra'] = 'bad', fn (&$r) => $r['bundle']['ciphertext'] = P::b64('changed ciphertext'), fn (&$r) => $r['bundle']['envelope']['header']['ciphertext_bytes'] = '01', fn (&$r) => $r['bundle']['wrap']['nonce'] = '=', fn (&$r) => $r['bundle']['envelope']['header']['context']['extra'] = true] as $mutate) {
            $r = $this->request();
            $mutate($r);
            $this->denied('MALFORMED_ENVELOPE', fn () => $this->commit($r));
        }
        $r = $this->request();
        $r['bundle']['envelope']['signature'] = P::b64(str_repeat("\0", 64));
        $this->denied('INVALID_SIGNATURE', fn () => $this->commit($r));
        foreach (['{"group_id":"a","group_id":"b"}', '{"x":"\ud800"}', '{"x":1e999}', "{\"x\":\"\xff\"}"] as $bytes) {
            $this->denied('INVALID_REQUEST', fn () => app(P::class)->decode('p04-api', 'object-commit', $bytes));
        }
        $this->assertSame(0, DB::table('object_revisions')->count());
    }

    public function test_current_device_session_generation_and_membership_are_rechecked_on_retries(): void
    {
        $this->commit();
        DB::table('auth_sessions')->where('secret_hash', hash('sha256', $this->secret()))->update(['state' => 'restricted']);
        $this->denied('SESSION_DEVICE_PROOF_REQUIRED', fn () => $this->commit());
        DB::table('auth_sessions')->where('secret_hash', hash('sha256', $this->secret()))->update(['state' => 'trusted']);
        DB::table('devices')->where('id', $this->fixture['accounts'][0]['device_id'])->update(['status' => 'revoked']);
        $this->denied('DEVICE_REVOKED', fn () => $this->commit());
        DB::table('devices')->where('id', $this->fixture['accounts'][0]['device_id'])->update(['status' => 'active']);
        DB::table('account_identities')->where('account_id', $this->fixture['accounts'][0]['account_id'])->update(['recovery_generation' => 1]);
        $this->denied('DEVICE_REVOKED', fn () => $this->commit());
        DB::table('account_identities')->where('account_id', $this->fixture['accounts'][0]['account_id'])->update(['recovery_generation' => 0]);
        DB::table('group_memberships')->where('group_id', $this->group())->where('account_id', $this->fixture['accounts'][0]['account_id'])->update(['status' => 'removed']);
        $this->denied('NOT_FOUND', fn () => $this->commit());
        $this->denied('NOT_FOUND', fn () => app(ScopedRepository::class)->receipt($this->secret(), $this->request()['bundle']['envelope']['header']['context']['operation_id']));
        $this->assertSame(1, DB::table('object_revisions')->count());
    }

    public function test_certificate_identity_expiry_and_current_capability_cannot_be_forged(): void
    {
        $account = $this->fixture['accounts'][0];
        $certificate = $account['certificate'];
        $certificate['signature'] = P::b64(str_repeat("\0", 64));
        DB::table('devices')->where('id', $account['device_id'])->update(['certificate_record' => json_encode($certificate)]);
        $this->denied('INVALID_SIGNATURE', fn () => $this->commit());
        DB::table('devices')->where('id', $account['device_id'])->update(['certificate_record' => json_encode($account['certificate']), 'can_sign_content' => false]);
        $this->denied('ROLE_FORBIDDEN', fn () => $this->commit());
        DB::table('devices')->where('id', $account['device_id'])->update(['can_sign_content' => true]);
        DB::table('auth_sessions')->where('secret_hash', hash('sha256', $this->secret()))->update(['expires_at' => now()->subSecond()]);
        $this->denied('SESSION_EXPIRED', fn () => $this->commit());
        DB::table('auth_sessions')->where('secret_hash', hash('sha256', $this->secret()))->update(['expires_at' => now()->addHour()]);
        DB::table('users')->where('id', $account['account_id'])->update(['status' => 'disabled']);
        $this->denied('SESSION_EXPIRED', fn () => $this->commit());
        $this->assertSame(0, DB::table('object_revisions')->count());
    }

    public function test_cas_parent_immutable_ids_and_idempotency_mismatch(): void
    {
        $first = $this->commit();
        $r = $this->request();
        $c = &$r['bundle']['envelope']['header']['context'];
        $c['revision_id'] = P::b64(str_repeat('u', 16));
        $c['action'] = 'update';
        $c['parents'] = $first['heads'];
        $this->denied('IDEMPOTENCY_MISMATCH', fn () => $this->commit($this->signed($r)));
        $c['operation_id'] = P::b64(str_repeat('v', 16));
        $second = $this->commit($this->signed($r));
        $this->assertSame($c['revision_id'], $second['heads'][0]['revision_id']);
        $c['revision_id'] = P::b64(str_repeat('w', 16));
        $c['operation_id'] = P::b64(str_repeat('x', 16));
        $this->denied('STALE_REVISION', fn () => $this->commit($this->signed($r)));
        $this->assertSame(2, DB::table('object_revisions')->count());
        $this->assertSame(1, DB::table('revision_parents')->count());
        foreach (['object_revisions', 'object_key_wraps'] as $table) {
            try {
                DB::table($table)->delete();
                $this->fail('Immutable table deleted');
            } catch (QueryException $e) {
                $this->assertSame('45000', $e->errorInfo[0]);
            }
        }
    }

    public function test_policy_roster_epoch_and_public_relation_context_are_enforced(): void
    {
        foreach ([['author', 'roster', 'digest', 'ROSTER_CHANGED'], ['policy', 'membership', 'digest', 'POLICY_CHANGED']] as [$one,$two,$field,$error]) {
            $r = $this->request();
            $r['bundle']['envelope']['header']['context'][$one][$two][$field] = P::b64(str_repeat('z', 32));
            $this->denied($error, fn () => $this->commit($this->signed($r)));
        }
        $r = $this->request();
        $r['bundle']['envelope']['header']['context']['policy']['key_epoch'] = '1';
        $this->denied('REKEY_REQUIRED', fn () => $this->commit($this->signed($r)));
        $r = $this->request();
        $r['bundle']['envelope']['header']['context']['thread_id'] = P::b64(str_repeat('q', 16));
        $this->denied('MALFORMED_ENVELOPE', fn () => $this->commit($this->signed($r)));
        foreach (['rekey_required' => 'REKEY_REQUIRED', 'history_closure_required' => 'HISTORY_CLOSURE_REQUIRED', 'restore_quarantined' => 'RESTORE_QUARANTINE'] as $field => $error) {
            DB::table('groups')->where('id', $this->group())->update([$field => true]);
            $this->denied($error, fn () => $this->commit());
            DB::table('groups')->where('id', $this->group())->update([$field => false]);
        }
    }

    public function test_quota_reservation_conversion_cancellation_and_security_reserve_isolation(): void
    {
        $svc = app(ReservationService::class);
        $id = P::b64(str_repeat('R', 16));
        $request = json_encode(['group_id' => $this->group(), 'reservation_id' => $id, 'bytes' => '100']);
        $first = $svc->reserve($this->secret(), $request);
        $this->assertSame($first, $svc->reserve($this->secret(), $request));
        $this->assertSame(100, (int) DB::table('quota_ledgers')->where('scope', 'global')->value('reserved_bytes'));
        $svc->cancel($this->secret(), $this->group(), $id);
        $svc->cancel($this->secret(), $this->group(), $id);
        $this->assertSame(0, (int) DB::table('quota_ledgers')->where('scope', 'global')->value('reserved_bytes'));
        $id = P::b64(str_repeat('S', 16));
        $svc->reserve($this->secret(), json_encode(['group_id' => $this->group(), 'reservation_id' => $id, 'bytes' => '100']));
        $actor = app(Authorization::class)->actor($this->secret());
        $svc->convert($this->secret(), $this->group(), $id, 80);
        $svc->convert($this->secret(), $this->group(), $id, 80);
        $this->assertSame(80, (int) DB::table('quota_ledgers')->where('scope', 'global')->value('committed_bytes'));
        $this->assertSame(0, (int) DB::table('quota_ledgers')->where('scope', 'global')->value('reserved_bytes'));
        $this->denied('INVALID_REQUEST', fn () => $svc->cancel($this->secret(), $this->group(), $id));
        $this->denied('QUOTA_EXCEEDED', fn () => $svc->reserve($this->secret(), json_encode(['group_id' => $this->group(), 'reservation_id' => P::b64(str_repeat('T', 16)), 'bytes' => '2147483649'])));
        DB::table('quota_ledgers')->where('scope', 'global')->update(['limit_bytes' => 80]);
        $this->denied('QUOTA_EXCEEDED', fn () => $this->commit());
        $this->assertSame(0, (int) DB::table('quota_ledgers')->where('scope', 'security')->value('reserved_bytes'));
    }

    public function test_sql_fault_after_counter_allocation_rolls_back_every_effect(): void
    {
        // Genuine SQL failure at the final receipt insertion, after revision/quota/event work.
        $before = DB::table('sync_counters')->value('sequence');
        try {
            $this->commit();
            $this->fail('Injected failure ignored');
        } catch (QueryException $e) {
            $this->assertSame('45000', $e->errorInfo[0]);
        }
        $this->assertSame($before, DB::table('sync_counters')->value('sequence'));
        foreach (['object_revisions', 'object_key_wraps', 'object_heads', 'sync_events', 'mutation_receipts'] as $table) {
            $this->assertSame(0, DB::table($table)->count());
        }
        $this->assertSame(0, (int) DB::table('quota_ledgers')->where('scope', 'global')->value('committed_bytes'));
        $retry = $this->request();
        $retry['bundle']['envelope']['header']['context']['operation_id'] = P::b64(str_repeat('Y', 16));
        $this->commit($this->signed($retry));
    }

    public function test_operator_readiness_and_invites_require_current_recent_admin_without_membership(): void
    {
        $this->get('http://api.anynote.test/api/v1/health/ready')->assertStatus(401);
        $this->withToken($this->secret())->get('http://api.anynote.test/api/v1/health/ready')->assertNotFound();
        $admin = app(AccountAdministration::class);
        $admin->bootstrap($this->fixture['accounts'][2]['account_id']);
        $this->denied('NOT_FOUND', fn () => $this->commit(null, 2));
        $this->withToken($this->secret(2))->get('http://api.anynote.test/api/v1/health/ready')->assertStatus(503);
        foreach (['queue', 'scheduler'] as $component) {
            DB::table('runtime_heartbeats')->updateOrInsert(['component' => $component], ['observed_at' => now()]);
        }
        $this->withToken($this->secret(2))->get('http://api.anynote.test/api/v1/health/ready')->assertOk()->assertExactJson(['status' => 'ready', 'database' => 'ready', 'queue' => 'ready', 'scheduler' => 'ready']);
        $r = ['recipient_binding_hash' => null, 'valid_hours' => 24];
        $result = $admin->invite($this->secret(2), json_encode($r));
        $this->assertSame(hash('sha256', $result['token']), DB::table('account_invites')->value('token_hash'));
        $this->assertFalse(DB::table('account_invites')->where('token_hash', $result['token'])->exists());
        $this->denied('ROLE_FORBIDDEN', fn () => $admin->invite($this->secret(), json_encode($r)));
        DB::table('auth_sessions')->where('secret_hash', hash('sha256', $this->secret(2)))->update(['authenticated_at' => now()->subMinutes(6)]);
        $this->denied('ROLE_FORBIDDEN', fn () => $admin->invite($this->secret(2), json_encode($r)));
        $this->withToken($this->secret(2))->get('http://api.anynote.test/api/v1/health/ready')->assertNotFound();
    }
}
