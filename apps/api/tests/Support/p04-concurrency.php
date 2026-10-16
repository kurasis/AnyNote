<?php

use App\Backend\ObjectService;
use App\Backend\QuotaLedger;
use App\Backend\ReservationService;
use App\Backend\SyncWriter;
use App\Crypto\PublicProtocol as P;
use App\Http\ApiException;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Tests\Support\SyntheticBackend;

// Runs only in the separately marked disposable P04 SQL test database.
require __DIR__.'/../../vendor/autoload.php';
$app = require __DIR__.'/../../bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

if (! app()->environment('testing') || config('database.connections.mariadb.database') !== 'anynote_p04_tests' || ! DB::getSchemaBuilder()->hasTable('p04_test_owner')) {
    throw new LogicException('Owned isolated test database required');
}
set_exception_handler(function (Throwable $e) {
    fwrite(STDERR, get_class($e).' at line '.$e->getLine().': '.$e->getMessage().PHP_EOL);
    exit(1);
});
$f = json_decode(file_get_contents(storage_path('framework/testing/p04-fixtures.json')), true, 32, JSON_THROW_ON_ERROR);
config(['api.service_id' => $f['service_id']]);
$mode = $argv[1] ?? 'parent';
if ($mode === 'commit' || $mode === 'reserve') {
    try {
        $index = (int) $argv[2];
        $bytes = file_get_contents(storage_path('framework/testing/'.$argv[3].'.json'));
        $result = $mode === 'commit' ? app(ObjectService::class)->commit($f['accounts'][$index]['session_secret'], $bytes) : app(ReservationService::class)->reserve($f['accounts'][$index]['session_secret'], $bytes);
        echo json_encode(['status' => 'PASS', 'result' => $result], JSON_THROW_ON_ERROR);
    } catch (ApiException $e) {
        echo json_encode(['status' => $e->errorCode]);
    }
    exit;
}
$event = ['group_id' => $f['groups'][0]['id'], 'kind' => 'thread', 'object_id' => $f['request']['object_id'], 'revision_id' => null, 'digest' => P::b64(str_repeat('e', 32))];
if ($mode === 'counter') {
    DB::select('SELECT 1');
    echo "READY\n";
    flush();
    $cursor = DB::transaction(fn () => app(SyncWriter::class)->append([$event]));
    echo json_encode(['status' => 'PASS', 'cursor' => $cursor]);
    exit;
}
$checks = 0;
function check(bool $condition): void
{
    global $checks;
    if (! $condition) {
        throw new RuntimeException('P04 concurrency/schema assertion failed');
    } $checks++;
}
function start(string $mode, int $index = 0, string $file = ''): array
{
    $pipes = [];
    $process = proc_open([PHP_BINARY, __FILE__, $mode, (string) $index, $file], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (! is_resource($process)) {
        throw new RuntimeException('Child failed');
    } fclose($pipes[0]);

    return [$process, $pipes];
}
function finish(array $child): array
{
    [$process,$pipes] = $child;
    $out = stream_get_contents($pipes[1]);
    $err = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    check(proc_close($process) === 0 && $err === '');

    return json_decode($out, true, 32, JSON_THROW_ON_ERROR);
}
function writeRequest(string $name, array $r): void
{
    file_put_contents(storage_path('framework/testing/'.$name.'.json'), json_encode($r, JSON_THROW_ON_ERROR));
}
function signRequest(array $r): array
{
    $h = &$r['bundle']['envelope']['header'];
    $r['action'] = $h['context']['action'];
    $r['bundle']['wrap']['context'] = $h['context'];
    $h['key_wrap_digest'] = P::digest('p02-v1', 'wrap', json_decode(json_encode($r['bundle']['wrap'])));
    $key = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair(str_repeat(chr(1), 32)));
    $r['bundle']['envelope']['signature'] = P::b64(sodium_crypto_sign_detached("AnyNote/p02-v1/sign/object-revision\0".P::canonical(json_decode(json_encode($h))), $key));

    return $r;
}
check(DB::table('users')->count() === 0);
SyntheticBackend::seed($f);
foreach ([fn () => app(QuotaLedger::class)->apply([], 1, 1), fn () => app(SyncWriter::class)->append([$event]), fn () => app(QuotaLedger::class)->lock($f['accounts'][0]['account_id'], $f['groups'][0]['id'])] as $call) {
    try {
        $call();
        throw new RuntimeException('Autocommit business write accepted');
    } catch (LogicException $e) {
        check($e->getMessage() === 'Transaction required');
    }
}
writeRequest('same', $f['request']);
$a = start('commit', 0, 'same');
$b = start('commit', 0, 'same');
$a = finish($a);
$b = finish($b);
check($a['status'] === 'PASS' && $a === $b);
check(DB::table('object_revisions')->count() === 1 && DB::table('mutation_receipts')->count() === 1 && DB::table('sync_events')->count() === 1);
$r = $f['request'];
$c = &$r['bundle']['envelope']['header']['context'];
$c['action'] = 'update';
$c['parents'] = $a['result']['heads'];
$c['revision_id'] = P::b64(str_repeat('a', 16));
$c['operation_id'] = P::b64(str_repeat('b', 16));
writeRequest('cas-a', signRequest($r));
$c['revision_id'] = P::b64(str_repeat('c', 16));
$c['operation_id'] = P::b64(str_repeat('d', 16));
writeRequest('cas-b', signRequest($r));
$a = start('commit', 0, 'cas-a');
$b = start('commit', 0, 'cas-b');
$statuses = [finish($a)['status'], finish($b)['status']];
sort($statuses);
check($statuses === ['PASS', 'STALE_REVISION']);
check(DB::table('object_revisions')->count() === 2 && DB::table('sync_events')->count() === 2 && DB::table('object_heads')->count() === 1);
$committed = (int) DB::table('quota_ledgers')->where('scope', 'global')->value('committed_bytes');
DB::table('quota_ledgers')->where('scope', 'global')->update(['limit_bytes' => $committed + 100]);
writeRequest('quota-a', ['group_id' => $f['groups'][0]['id'], 'reservation_id' => P::b64(str_repeat('r', 16)), 'bytes' => '80']);
writeRequest('quota-b', ['group_id' => $f['groups'][1]['id'], 'reservation_id' => P::b64(str_repeat('s', 16)), 'bytes' => '80']);
$a = start('reserve', 0, 'quota-a');
$b = start('reserve', 2, 'quota-b');
$statuses = [finish($a)['status'], finish($b)['status']];
sort($statuses);
check($statuses === ['PASS', 'QUOTA_EXCEEDED']);
check((int) DB::table('quota_ledgers')->where('scope', 'global')->value('reserved_bytes') === 80 && DB::table('quota_reservations')->count() === 1);
check((int) DB::table('quota_ledgers')->where('scope', 'security')->value('reserved_bytes') === 0);
// Two connected processes contend on the transactional counter. The child declares
// readiness before its transaction; no product code waits on external I/O.
$counterObservations = [];
foreach (['commit', 'rollback'] as $outcome) {
    $before = (int) DB::table('sync_counters')->value('sequence');
    DB::beginTransaction();
    $cursor = app(SyncWriter::class)->append([$event]);
    $child = start('counter');
    check(trim(fgets($child[1][1])) === 'READY');
    $read = [$child[1][1]];
    $write = null;
    $except = null;
    check(stream_select($read, $write, $except, 0, 250000) === 0);
    $configuration = config('database.connections.mariadb');
    $observer = new PDO('mysql:host='.$configuration['host'].';dbname=anynote_p04_tests', $configuration['username'], $configuration['password'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $observedWhileBlocked = (int) $observer->query('SELECT sequence FROM sync_counters WHERE id=1')->fetchColumn();
    check($observedWhileBlocked === $before);
    if ($outcome === 'commit') {
        DB::commit();
    } else {
        DB::rollBack();
    }
    $result = finish($child);
    check($result['status'] === 'PASS');
    check((int) $result['cursor']['sequence'] === $before + ($outcome === 'commit' ? 2 : 1));
    check((int) DB::table('sync_counters')->value('sequence') === (int) $result['cursor']['sequence']);
    $counterObservations[] = ['injection' => 'A holds allocated transactional counter; connected B blocked for at least250ms; independent PDO observer polls before A resolves', 'a_outcome' => $outcome, 'before_sequence' => (string) $before, 'a_uncommitted_sequence' => $cursor['sequence'], 'observer_while_b_blocked' => (string) $observedWhileBlocked, 'b_committed_sequence' => $result['cursor']['sequence'], 'after_sequence' => (string) DB::table('sync_counters')->value('sequence')];
}
check((int) DB::selectOne('SELECT @@innodb_flush_log_at_trx_commit AS value')->value === 1);
check((int) DB::selectOne('SELECT @@sync_binlog AS value')->value === 1);
check(DB::selectOne('SELECT @@session.sql_mode AS value')->value !== '' && str_contains(DB::selectOne('SELECT @@session.sql_mode AS value')->value, 'STRICT'));
$columns = DB::select('SELECT TABLE_NAME,COLUMN_NAME,DATA_TYPE,ENGINE FROM information_schema.COLUMNS JOIN information_schema.TABLES USING (TABLE_SCHEMA,TABLE_NAME) WHERE TABLE_SCHEMA=DATABASE()');
foreach ($columns as $column) {
    check(! in_array($column->COLUMN_NAME, ['title', 'body', 'filename', 'markdown', 'search_phrase'], true));
    check($column->ENGINE === 'InnoDB');
}
check(DB::table('object_revisions')->value('ciphertext') === P::binary($f['request']['bundle']['ciphertext']));
try {
    DB::table('sync_counters')->where('id', 1)->update(['sequence' => '9223372036854775808']);
    throw new RuntimeException('u63 overflow accepted');
} catch (QueryException $e) {
    check($e->errorInfo[0] === '23000');
}
$tables = DB::select('SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()');
$constraints = DB::select('SELECT CONSTRAINT_NAME FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE()');
echo json_encode(['status' => 'PASS', 'checks' => $checks, 'tables' => count($tables), 'constraints' => count($constraints), 'parallel_processes' => 8, 'same_body_retry' => 'PASS', 'competing_parent_cas' => 'PASS', 'cross_group_quota_race' => 'PASS', 'counter_commit_order' => 'PASS', 'counter_rollback_reuse' => 'PASS', 'counter_observations' => $counterObservations, 'sql_durability_configuration' => 'PASS', 'plaintext_column_inspection' => 'PASS', 'u63_overflow_rejection' => 'PASS'], JSON_THROW_ON_ERROR);
