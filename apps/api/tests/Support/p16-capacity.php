<?php

// Bounded bulk capacity fixture: verifies every client signature/context, installs
// retained history in batches; not a claim of 100,000 HTTP publication requests.
use App\Backend\QuotaLedger;
use App\Crypto\PublicProtocol as P;
use App\Devices\Protocol;
use App\Http\ApiException;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;

require '/app/vendor/autoload.php';
$app = require '/app/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();
$count = 0;
$phase = 'metadata';
set_exception_handler(function (Throwable $error) use (&$count, &$phase): void {
    fwrite(STDERR, json_encode(['status' => 'FAIL', 'phase' => $phase, 'verified_rows' => $count, 'class' => get_class($error), 'code' => $error instanceof ApiException ? $error->errorCode : $error->getCode(), 'driver_code' => $error instanceof QueryException ? ($error->errorInfo[1] ?? null) : null, 'source' => basename($error->getFile()), 'line' => $error->getLine()], JSON_THROW_ON_ERROR)."\n");
    exit(1);
});
if (! hash_equals((string) getenv('ANYNOTE_P16_OWNER'), (string) DB::table('p16_test_owner')->value('owner'))) {
    throw new LogicException('Owned capacity database required');
}
$meta = json_decode(fgets(STDIN, 65536), false, 32, JSON_THROW_ON_ERROR);
$device = DB::table('devices')->where('id', $meta->device_id)->where('account_id', $meta->account_id)->where('status', 'active')->first();
$object = DB::table('objects')->where('id', $meta->object_id)->where('group_id', $meta->group_id)->first();
if (! $device || ! $object || $meta->count !== 100000) {
    throw new LogicException('Exact registered capacity scope required');
}
$protocol = app(P::class);
$count = 0;
$bytes = 0;
$previous = $meta->parent;
$started = hrtime(true);
while ($count < $meta->count) {
    $revisions = [];
    $wraps = [];
    $parents = [];
    $batchBytes = 0;
    for ($n = 0; $n < 500 && $count < $meta->count; $n++, $count++) {
        $line = fgets(STDIN, 1048576);
        if ($line === false) {
            throw new LogicException('Truncated capacity fixture');
        }
        $phase = 'verify-bundle';
        $bundle = $protocol->bundle($line, $device->signing_key);
        $c = $bundle->envelope->header->context;
        if ($c->group_id !== $meta->group_id || $c->object_id !== $meta->object_id || $c->author->account_id !== $meta->account_id || $c->author->device_id !== $meta->device_id || ! Protocol::equal($c->parents, [$previous]) || $c->action !== 'update') {
            throw new LogicException('Unbound capacity revision');
        }
        $cipher = P::binary($bundle->ciphertext);
        $digest = P::digest('p02-v1', 'envelope', $bundle->envelope);
        $revisions[] = ['revision_id' => $c->revision_id, 'object_id' => $c->object_id, 'group_id' => $c->group_id, 'author_account_id' => $c->author->account_id, 'author_device_id' => $c->author->device_id, 'operation_id' => $c->operation_id, 'epoch_number' => (int) $c->policy->key_epoch, 'payload_schema' => $c->payload_schema, 'envelope_digest' => $digest, 'signed_envelope' => P::canonical($bundle->envelope), 'ciphertext' => $cipher, 'ciphertext_bytes' => strlen($cipher)];
        $wraps[] = ['revision_id' => $c->revision_id, 'wrap_record' => P::canonical($bundle->wrap), 'ciphertext_bytes' => 48];
        $parents[] = ['group_id' => $c->group_id, 'object_id' => $c->object_id, 'revision_id' => $c->revision_id, 'parent_revision_id' => $previous->revision_id];
        $previous = (object) ['revision_id' => $c->revision_id, 'envelope_digest' => $digest];
        $batchBytes += strlen($cipher) + 48;
    }
    $phase = 'insert-batch';
    DB::transaction(function () use ($revisions, $wraps, $parents, $meta, $batchBytes) {
        $ledger = app(QuotaLedger::class);
        $ledger->apply($ledger->lock($meta->account_id, $meta->group_id), $batchBytes, 0);
        DB::table('object_revisions')->insert($revisions);
        DB::table('object_key_wraps')->insert($wraps);
        DB::table('revision_parents')->insert($parents);
    });
    $bytes += $batchBytes;
}
DB::table('object_heads')->where('object_id', $meta->object_id)->update(['revision_id' => $previous->revision_id]);
if (! feof(STDIN) && trim(stream_get_contents(STDIN)) !== '') {
    throw new LogicException('Unexpected extra capacity records');
}
echo json_encode(['status' => 'PASS', 'retained_signed_revisions_inserted' => $count, 'actual_logical_ciphertext_bytes' => $bytes, 'elapsed_ms' => (int) ((hrtime(true) - $started) / 1000000), 'peak_php_allocated_bytes' => memory_get_peak_usage(true), 'http_publications' => false, 'every_bundle_public_signature_verified' => true, 'quota_journal_consistent' => app(QuotaLedger::class)->reconcile()['differences'] === []], JSON_THROW_ON_ERROR)."\n";
