<?php

use App\Auth\Maintenance;
use App\Auth\Policy;
use App\Backend\AccountAdministration;
use App\Backend\Authorization;
use App\Backend\QuotaLedger;
use App\Backend\SyncWriter;
use App\Crypto\PublicProtocol as P;
use App\Files\Service;
use App\Http\ApiException;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

// Console-only control of one explicitly owned synthetic database, never an HTTP auth bypass.
require __DIR__.'/../../vendor/autoload.php';
$app = require __DIR__.'/../../bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

if (! $app->runningInConsole() || ! $app->environment('testing') || config('database.connections.mariadb.database') !== 'anynote_p06_tests' || ! hash_equals((string) DB::table('p06_test_owner')->value('owner'), (string) getenv('ANYNOTE_P06_TEST_OWNER'))) {
    throw new LogicException('Only the owned synthetic P06 database is allowed');
}
$op = $argv[1] ?? '';
$value = match ($op) {
    'p12-budget' => (function () {
        $v = json_decode(stream_get_contents(STDIN));
        if (! P::counter($v->available_bytes ?? '', '1000000000')) {
            throw new LogicException('Invalid synthetic quota budget');
        }

        return DB::transaction(function () use ($v) {
            $ledger = DB::table('quota_ledgers')->where('scope', 'global')->lockForUpdate()->first();
            $next = (int) $ledger->committed_bytes + (int) $ledger->reserved_bytes + (int) $v->available_bytes;
            if ($next > 100000000000) {
                throw new LogicException('Synthetic quota cannot exceed the product limit');
            }
            DB::table('quota_ledgers')->where('scope', 'global')->update(['limit_bytes' => $next]);

            return ['previous_limit_bytes' => (string) $ledger->limit_bytes];
        });
    })(),
    'p12-budget-restore' => (function () {
        $v = json_decode(stream_get_contents(STDIN));
        if (! P::counter($v->limit_bytes ?? '', '100000000000')) {
            throw new LogicException('Invalid synthetic quota restore');
        }
        DB::table('quota_ledgers')->where('scope', 'global')->update(['limit_bytes' => (int) $v->limit_bytes]);

        return ['status' => 'PASS'];
    })(),
    'p12-fault-on' => (function () {
        DB::unprepared("CREATE TRIGGER p12_fault BEFORE INSERT ON mutation_receipts FOR EACH ROW BEGIN IF NEW.family = 'file' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Synthetic file receipt fault'; END IF; END");

        return ['status' => 'armed'];
    })(),
    'p12-fault-off' => (function () {
        DB::unprepared('DROP TRIGGER IF EXISTS p12_fault');

        return ['status' => 'disarmed'];
    })(),
    'p12-transaction-state' => (function () {
        $counts = [];
        foreach (['file_chunks', 'publication_journal', 'mutation_receipts', 'quota_movements', 'sync_events'] as $table) {
            $counts[$table] = DB::table($table)->count();
        }

        return ['counts' => $counts, 'counter' => (string) DB::table('sync_counters')->value('sequence'),
            'quota' => DB::table('quota_ledgers')->orderBy('scope')->get(['scope', 'committed_bytes', 'reserved_bytes'])->all()];
    })(),
    'p12-collect' => app(Service::class)->collect(),
    'p12-reconcile' => app(QuotaLedger::class)->reconcile(),
    'p12-expire' => (function () {
        $v = json_decode(stream_get_contents(STDIN));
        if (! P::isBinary($v->upload_id ?? '', 16)) {
            throw new LogicException('Invalid synthetic upload');
        }
        DB::table('upload_sessions')->where('id', $v->upload_id)->whereIn('state', ['reserved', 'receiving'])->update(['expires_at' => now()->subSeconds(1)]);

        return ['status' => 'PASS'];
    })(),
    'p12-pruned-proof' => (function () {
        $v = json_decode(stream_get_contents(STDIN));
        if (! P::isBinary($v->file_version_id ?? '', 16)) {
            throw new LogicException('Invalid synthetic file');
        }
        $row = DB::table('file_versions')->where('id', $v->file_version_id)->where('state', 'deleted')->first();
        if (! $row) {
            throw new LogicException('Synthetic file is not pruned');
        }

        return ['retained_fields' => array_keys(json_decode($row->manifest_record, true))];
    })(),
    'p12-file-state' => ['uploads' => DB::table('upload_sessions')->count(), 'committed_files' => DB::table('file_versions')->where('state', 'committed')->count(), 'file_pins' => DB::table('snapshot_file_pins')->count()],
    'p11-state' => (function () {
        return ['snapshots' => DB::table('snapshot_sessions')->count(), 'active' => DB::table('snapshot_sessions')->where('state', 'active')->count(), 'pins' => DB::table('reference_pins')->count(), 'items' => DB::table('snapshot_items')->count(), 'pages' => DB::table('snapshot_pages')->count(), 'catalog' => DB::table('snapshot_catalog')->count()];
    })(),
    'p11-hidden-burst' => (function () {
        // Console-only unsigned transport hints, not an authentication/content issuer.
        $v = json_decode(stream_get_contents(STDIN));
        if (! $v instanceof stdClass || ! P::isBinary($v->account_id ?? null, 16) || ! is_int($v->count ?? null) || $v->count < 1 || $v->count > 3000 || ! DB::table('users')->where('id', $v->account_id)->exists()) {
            throw new LogicException('Invalid synthetic namespace hint request');
        }
        $cursor = null;
        for ($n = 0; $n < $v->count; $n += 100) {
            $count = min(100, $v->count - $n);
            $cursor = DB::transaction(function () use ($v, $count) {
                $events = [];
                for ($k = 0; $k < $count; $k++) {
                    $events[] = ['audience_account_id' => $v->account_id, 'group_id' => null, 'kind' => 'fixture-namespace', 'object_id' => P::b64(random_bytes(16)), 'revision_id' => null, 'digest' => P::b64(random_bytes(32))];
                }

                return app(SyncWriter::class)->append($events);
            });
        }

        return ['status' => 'appended', 'cursor' => $cursor];
    })(),
    'p11-expire' => (function () {
        $v = json_decode(stream_get_contents(STDIN));
        if (! $v instanceof stdClass || ! P::isBinary($v->id ?? null, 16)) {
            throw new LogicException('Invalid synthetic snapshot');
        }
        DB::table('snapshot_sessions')->where('id', $v->id)->update(['expires_at' => now()->subMinute()]);

        return ['status' => 'expired'];
    })(),
    'p11-fault-on' => (function () {
        DB::unprepared("CREATE TRIGGER p11_fault BEFORE INSERT ON snapshot_pages FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Synthetic snapshot materialization fault'");

        return ['status' => 'installed'];
    })(),
    'p11-fault-off' => (function () {
        DB::unprepared('DROP TRIGGER IF EXISTS p11_fault');

        return ['status' => 'removed'];
    })(),
    'p09-state' => (function () {
        $counts = [];
        foreach (['objects', 'object_revisions', 'object_heads', 'object_key_wraps', 'revision_parents', 'private_group_geneses', 'mutation_receipts', 'sync_events'] as $t) {
            $counts[$t] = DB::table($t)->count();
        }

        return ['counts' => $counts, 'counter' => (string) DB::table('sync_counters')->value('sequence'), 'quotas' => DB::table('quota_ledgers')->orderBy('scope')->get(['scope', 'committed_bytes', 'reserved_bytes'])->map(fn ($x) => ['scope' => $x->scope, 'committed' => (string) $x->committed_bytes, 'reserved' => (string) $x->reserved_bytes])->all()];
    })(),
    'p09-fault-on' => (function () {
        DB::unprepared("CREATE TRIGGER anynote_p09_commit_fault BEFORE INSERT ON mutation_receipts FOR EACH ROW BEGIN IF NEW.family='object' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='P09_SYNTHETIC_FAULT'; END IF; END");

        return ['status' => 'installed'];
    })(),
    'p09-fault-off' => (function () {
        DB::unprepared('DROP TRIGGER IF EXISTS anynote_p09_commit_fault');

        return ['status' => 'removed'];
    })(),
    'p10-fault-on' => (function () {
        DB::unprepared("CREATE TRIGGER p10_fault BEFORE INSERT ON group_security_receipts FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Synthetic security receipt fault'");

        return ['status' => 'armed'];
    })(),
    'p10-fault-off' => (function () {
        DB::unprepared('DROP TRIGGER IF EXISTS p10_fault');

        return ['status' => 'disarmed'];
    })(),
    'p10-state' => (function () {
        $counts = [];
        foreach (['groups', 'group_memberships', 'group_policy_events', 'group_key_epochs', 'group_transition_journal', 'group_security_receipts', 'security_transition_staging', 'security_transition_pages', 'key_envelopes'] as $t) {
            $counts[$t] = DB::table($t)->count();
        }

        return ['counts' => $counts, 'counter' => (string) DB::table('sync_counters')->value('sequence'), 'quota' => DB::table('quota_ledgers')->orderBy('scope')->get(['scope', 'committed_bytes', 'reserved_bytes'])->all()];
    })(),
    'p09-quota-on' => (function () {
        DB::statement("UPDATE quota_ledgers SET limit_bytes=committed_bytes+reserved_bytes WHERE scope='global'");

        return ['status' => 'bounded'];
    })(),
    'p09-quota-off' => (function () {
        DB::table('quota_ledgers')->where('scope', 'global')->update(['limit_bytes' => 100000000000]);

        return ['status' => 'restored'];
    })(),
    'p09-inspect' => (function () {
        $v = json_decode(stream_get_contents(STDIN), true, 33, JSON_THROW_ON_ERROR);
        $markers = $v['markers'] ?? [];
        if (! is_array($markers) || ! count($markers) || count($markers) > 32) {
            throw new LogicException('Invalid inspection');
        }
        foreach ($markers as $m) {
            if (! is_string($m) || strlen($m) < 8 || strlen($m) > 4096) {
                throw new LogicException('Invalid marker');
            }
        }
        $seen = 0;
        foreach (DB::select('SHOW TABLES') as $item) {
            $t = array_values((array) $item)[0];
            if (! preg_match('/^[a-z0-9_]+$/D', $t)) {
                throw new LogicException('Invalid table');
            }
            foreach (DB::table($t)->cursor() as $row) {
                $seen++;
                foreach ((array) $row as $cell) {
                    if (! is_string($cell)) {
                        continue;
                    }foreach ($markers as $m) {
                        if (str_contains($cell, $m)) {
                            return ['status' => 'FAIL', 'location' => 'SQL', 'rows' => $seen];
                        }
                    }
                }
            }
        }
        foreach (glob(storage_path('logs/*')) as $path) {
            if (! is_file($path) || filesize($path) > 8388608) {
                continue;
            }$bytes = file_get_contents($path);
            foreach ($markers as $m) {
                if (str_contains($bytes, $m)) {
                    return ['status' => 'FAIL', 'location' => 'log', 'rows' => $seen];
                }
            }
        }

        return ['status' => 'PASS', 'rows' => $seen, 'markers' => count($markers)];
    })(),
    'ready' => (function () {
        Policy::check();
        if (DB::selectOne('SELECT 1 AS ready')->ready !== 1 || ! Schema::hasTable('sessions')) {
            throw new LogicException('Not ready');
        }

        return ['status' => 'PASS', 'database' => 'owned P06', 'policy' => 'HTTPS, exact RP/origins, private OAuth key'];
    })(),
    'invite' => (function () {
        $token = P::b64(random_bytes(32));
        DB::table('account_invites')->insert(['id' => P::b64(random_bytes(16)), 'creator_id' => null, 'bootstrap' => true, 'token_hash' => hash('sha256', $token), 'status' => 'pending', 'expires_at' => now()->addHours(1)]);

        return ['token' => $token];
    })(),
    'counts' => (function () {
        $result = [];
        foreach (['users', 'account_identities', 'devices', 'account_roster_events', 'passkey_credentials', 'auth_sessions', 'oauth_access', 'oauth_codes', 'refresh_tokens'] as $table) {
            $result[$table] = DB::table($table)->count();
        }

        return $result;
    })(),
    'bootstrap-admin' => (function () {
        app(AccountAdministration::class)->bootstrap(DB::table('users')->orderBy('created_at')->value('id'));

        return ['status' => 'ok'];
    })(),
    'content-authorization' => (function () {
        $secret = stream_get_contents(STDIN, 8193);
        try {
            DB::transaction(fn () => app(Authorization::class)->actor($secret));

            return ['status' => 'ALLOWED'];
        } catch (ApiException $e) {
            return ['status' => 'DENIED', 'code' => $e->errorCode];
        } finally {
            sodium_memzero($secret);
        }
    })(),
    'expire-challenges' => (function () {
        DB::table('auth_challenges')->update(['expires_at' => now()->subMinutes(1)]);

        return ['status' => 'ok'];
    })(),
    'expire-invitations' => (function () {
        DB::table('account_invites')->where('status', 'pending')->update(['expires_at' => now()->subMinutes(1)]);

        return ['status' => 'ok'];
    })(),
    'age-auth' => (function () {
        DB::table('auth_sessions')->update(['authenticated_at' => now()->subMinutes(6)]);

        return ['status' => 'ok'];
    })(),
    'expire-pwa' => (function () {
        DB::table('auth_sessions')->where('transport', 'pwa')->where('state', '!=', 'revoked')->update(['expires_at' => now()->subMinute()]);

        return ['status' => 'ok'];
    })(),
    'prune-expired' => (function () {
        $before = DB::table('auth_challenges')->count();
        DB::table('auth_challenges')->update(['expires_at' => now()->subDays(2)]);
        $count = app(Maintenance::class)->prune();

        return ['expired_challenges' => $before, 'remaining_challenges' => DB::table('auth_challenges')->count(), 'removed' => $count, 'users' => DB::table('users')->count(), 'devices' => DB::table('devices')->count(), 'rosters' => DB::table('account_roster_events')->count()];
    })(),
    'expire-rates' => (function () {
        DB::table('auth_rate_buckets')->update(['expires_at' => now()->subMinute()]);

        return ['status' => 'ok'];
    })(),
    'clear-rates' => (function () {
        DB::table('auth_rate_buckets')->delete();

        return ['status' => 'ok'];
    })(),
    // Test-only legacy fixture: refuse any P08/group data; preserve real synthetic P06 rows.
    'p08-legacy-fixture' => (function () {
        foreach (['enrollment_sessions', 'device_relay_frames', 'device_transition_receipts', 'account_security_notifications', 'account_settings_genesis', 'groups'] as $table) {
            if (DB::table($table)->exists()) {
                throw new LogicException('Legacy fixture requires no P08 or group data');
            }
        }
        foreach (DB::table('account_roster_events')->get() as $event) {
            if (json_decode($event->signed_record)->body->kind !== 'register') {
                throw new LogicException('Legacy fixture requires initial P06 rosters only');
            }
        }
        foreach (['device_relay_frames', 'device_transition_receipts', 'account_security_notifications', 'account_settings_genesis'] as $table) {
            Schema::drop($table);
        }
        Schema::table('enrollment_sessions', function ($t) {
            $t->dropColumn(['creator_session_id', 'new_session_id', 'approver_device_id', 'new_device_id', 'mode', 'public_record', 'offer_record', 'transcript_record', 'approval_record', 'event_record']);
        });
        Schema::table('devices', function ($t) {
            $t->dropColumn(['parent_device_id', 'platform', 'enrolled_at']);
        });
        Schema::table('account_identities', function ($t) {
            $t->dropColumn('device_limit');
        });
        DB::table('migrations')->where('migration', '2026_10_12_000005_create_trusted_device_lifecycle')->delete();

        return ['status' => 'owned empty P08 schema removed for legacy-upgrade fixture'];
    })(),
    'p08-state' => (function () {
        $result = [];
        foreach (['devices', 'account_roster_events', 'device_transition_receipts', 'sync_events', 'key_envelopes'] as $table) {
            $result[$table] = DB::table($table)->count();
        }
        $result['heads'] = DB::table('account_identities')->orderBy('account_id')->get(['account_id', 'roster_sequence', 'roster_digest', 'recovery_generation']);
        $result['sessions'] = DB::table('auth_sessions')->orderBy('id')->get(['id', 'state', 'device_id', 'recovery_generation']);

        return $result;
    })(),
    'p08-fault-on' => (function () {
        DB::unprepared("CREATE TRIGGER p08_fault BEFORE INSERT ON account_roster_events FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic P08 write failure'");

        return ['status' => 'armed'];
    })(),
    'p08-fault-off' => (function () {
        DB::unprepared('DROP TRIGGER IF EXISTS p08_fault');

        return ['status' => 'disarmed'];
    })(),
    'p08-expire-pending' => (function () {
        DB::table('enrollment_sessions')->whereIn('state', ['pending', 'approved'])->update(['expires_at' => now()->subMinute()]);

        return ['status' => 'ok'];
    })(),
    'p08-fill-content' => (function () {
        DB::table('quota_ledgers')->where('scope', 'global')->update(['committed_bytes' => DB::raw('limit_bytes')]);

        return ['status' => 'ok'];
    })(),
    'p08-release-content' => (function () {
        // Undo only the owned synthetic saturation; preserve all actual charges/data.
        return DB::transaction(function () {
            $global = DB::table('quota_ledgers')->where('scope', 'global')->lockForUpdate()->first();
            if ($global->committed_bytes == $global->limit_bytes) {
                $actual = DB::table('quota_ledgers')->where('scope', 'like', 'account/%')->sum('committed_bytes');
                if ($actual > $global->limit_bytes) {
                    throw new LogicException('Synthetic quota reconciliation failed');
                }
                DB::table('quota_ledgers')->where('scope', 'global')->update(['committed_bytes' => $actual]);
            }

            return ['status' => 'restored'];
        });
    })(),
    'p08-exhaust-reserve' => (function () {
        DB::table('quota_ledgers')->where('scope', 'security')->update(['reserved_bytes' => DB::raw('limit_bytes - committed_bytes')]);

        return ['status' => 'ok'];
    })(),
    'p08-release-reserve' => (function () {
        DB::table('quota_ledgers')->where('scope', 'security')->update(['reserved_bytes' => 0]);

        return ['status' => 'ok'];
    })(),
    'p08-remove-membership' => (function () {
        DB::table('group_memberships')->update(['status' => 'removed']);

        return ['status' => 'ok'];
    })(),
    'p08-restore-membership' => (function () {
        DB::table('group_memberships')->update(['status' => 'active']);

        return ['status' => 'ok'];
    })(),
    default => throw new LogicException('Unknown synthetic control operation'),
};
echo json_encode($value, JSON_THROW_ON_ERROR)."\n";
