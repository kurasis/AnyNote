<?php

use App\Auth\Maintenance;
use App\Auth\Policy;
use App\Backend\AccountAdministration;
use App\Backend\Authorization;
use App\Crypto\PublicProtocol as P;
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
