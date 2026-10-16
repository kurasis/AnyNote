<?php

namespace Tests\Feature;

use App\Backend\Authorization;
use App\Crypto\PublicProtocol;
use App\Files\BlobStore;
use App\Http\ApiException;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use PHPUnit\Framework\Attributes\Group;
use Tests\Support\SyntheticBackend;
use Tests\TestCase;

#[Group('backend')]
final class RestoreFenceTest extends TestCase
{
    private array $fixture;

    private string $fence;

    protected function setUp(): void
    {
        parent::setUp();
        $this->assertSame('anynote_p04_tests', config('database.connections.mariadb.database'));
        $this->app['env'] = 'testing';
        Artisan::call('migrate', ['--no-interaction' => true]);
        DB::beginTransaction();
        $this->fixture = json_decode(file_get_contents(storage_path('framework/testing/p04-fixtures.json')), true, 32, JSON_THROW_ON_ERROR);
        SyntheticBackend::seed($this->fixture);
        $this->fence = sys_get_temp_dir().'/anynote-restore-test-'.bin2hex(random_bytes(16));
        config(['operations.recovery_fence' => $this->fence, 'api.service_id' => $this->fixture['service_id']]);
    }

    protected function tearDown(): void
    {
        if (is_file($this->fence)) {
            unlink($this->fence);
        }
        while (DB::transactionLevel() > 0) {
            DB::rollBack();
        }
        parent::tearDown();
    }

    public function test_host_fence_prevents_restored_cookie_and_every_auth_entry_point(): void
    {
        file_put_contents($this->fence, 'Synthetic isolated restore');
        foreach (['/me/storage', '/auth/csrf', '/auth/passkeys/options', '/auth/native/token', '/me/recovery-envelopes'] as $path) {
            $this->get('http://api.anynote.test/api/v1'.$path)->assertJsonPath('error.code', 'RESTORE_QUARANTINE')->assertHeader('Cache-Control', 'no-store, private');
        }
    }

    public function test_database_fence_survives_a_missing_host_file_and_denies_preflight(): void
    {
        DB::table('operations_restore_state')->where('singleton', 1)->update(['quarantined' => true]);
        $this->assertFileDoesNotExist($this->fence);
        $this->get('http://api.anynote.test/api/v1/capabilities')->assertJsonPath('error.code', 'RESTORE_QUARANTINE');
        $this->options('http://api.anynote.test/api/v1/auth/passkeys/verify')->assertJsonPath('error.code', 'RESTORE_QUARANTINE');
    }

    public function test_quarantined_group_cannot_be_read_or_modified_with_an_old_valid_actor(): void
    {
        $authorization = app(Authorization::class);
        $actor = $authorization->actor($this->fixture['accounts'][0]['session_secret']);
        $group = $this->fixture['groups'][0]['id'];
        DB::table('groups')->where('id', $group)->update(['restore_quarantined' => true]);
        foreach (['read', 'write', 'owner'] as $permission) {
            try {
                $authorization->group($actor, $group, $permission);
                $this->fail('Restored old authority was admitted');
            } catch (ApiException $error) {
                $this->assertSame('RESTORE_QUARANTINE', $error->errorCode);
            }
        }
    }

    public function test_expired_unpublished_grants_are_collected_without_erasing_burned_commitments_or_committed_pages(): void
    {
        $group = $this->fixture['groups'][0]['id'];
        $descriptor = '{"intent":{"body":{"key_commitment":"PUBLIC_BURNED_COMMITMENT"}}}';
        $ids = [];
        foreach (['staged', 'committed'] as $state) {
            $id = PublicProtocol::b64(random_bytes(16));
            $ids[] = $id;
            DB::table('security_transition_staging')->insert(['id' => $id, 'group_id' => $group, 'pending_group_id' => null, 'expected_policy_digest' => str_repeat('A', 43), 'expected_rosters' => '[]', 'signed_descriptor' => $descriptor, 'state' => $state, 'expires_at' => now()->subDays(3)]);
            DB::table('security_transition_pages')->insert(['id' => PublicProtocol::b64(random_bytes(16)), 'transition_id' => $id, 'page_index' => 0, 'digest' => str_repeat('A', 43), 'page_record' => '{}']);
        }
        $this->assertSame(0, Artisan::call('operations:maintain'));
        $first = json_decode(Artisan::output(), true, 32, JSON_THROW_ON_ERROR);
        $this->assertSame('PASS', $first['status']);
        $this->assertSame(1, $first['expired_unpublished_grant_pages']);
        $this->assertSame(0, Artisan::call('operations:maintain'));
        $second = json_decode(Artisan::output(), true, 32, JSON_THROW_ON_ERROR);
        $this->assertSame(0, $second['expired_unpublished_grant_pages']);
        $this->assertSame($descriptor, DB::table('security_transition_staging')->where('id', $ids[0])->value('signed_descriptor'));
        $this->assertSame('expired', DB::table('security_transition_staging')->where('id', $ids[0])->value('state'));
        $this->assertSame(1, DB::table('security_transition_pages')->where('transition_id', $ids[1])->count());
    }

    public function test_collector_cannot_delete_another_disposable_database_blob_namespace(): void
    {
        $original = storage_path();
        $temporary = sys_get_temp_dir().'/anynote-p16-scope-'.bin2hex(random_bytes(16));
        $this->app->useStoragePath($temporary);
        try {
            $legacy = storage_path('app/private/p12-blobs');
            mkdir($legacy, 0700, true);
            $id = PublicProtocol::b64(random_bytes(16));
            file_put_contents($legacy.'/'.$id, 'PUBLIC separate-database sentinel');
            touch($legacy.'/'.$id, time() - 400000);
            $blobs = app(BlobStore::class);
            $this->assertNotSame($legacy, $blobs->root());
            $owned = $blobs->path(PublicProtocol::b64(random_bytes(16)));
            file_put_contents($owned, 'PUBLIC disposable orphan');
            touch($owned, time() - 400000);
            $this->assertSame(1, $blobs->orphans());
            $this->assertFileDoesNotExist($owned);
            $this->assertSame('PUBLIC separate-database sentinel', file_get_contents($legacy.'/'.$id));
            unlink($legacy.'/'.$id);
        } finally {
            $this->app->useStoragePath($original);
            File::deleteDirectory($temporary);
        }
    }
}
