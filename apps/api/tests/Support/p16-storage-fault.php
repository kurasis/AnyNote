<?php

// Console-only bounded tmpfs faults; excluded from the runtime image.
use App\Files\BlobStore;
use App\Files\DirectoryDurability;
use App\Http\ApiException;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\DB;

require '/app/vendor/autoload.php';
$app = require '/app/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();
if (! hash_equals((string) getenv('ANYNOTE_P16_OWNER'), (string) DB::table('p16_test_owner')->value('owner')) || ! is_dir('/fault')) {
    throw new LogicException('Owned synthetic DB and bounded tmpfs required');
}
$app->useStoragePath('/fault');
config(['operations.reserve_bytes' => 0, 'operations.reserve_fraction' => 0.0]);
$blobs = app(BlobStore::class);
$root = $blobs->root();
$input = fopen('php://temp', 'w+b');
fwrite($input, str_repeat('x', 65536));
rewind($input);
$before = DB::table('quota_ledgers')->orderBy('scope')->get()->toJson();
$valid = $blobs->stage($input, 65536);
$committed = file_get_contents($blobs->path($valid['blob_id']));
$fill = fopen('/fault/fill', 'xb');
$observed = false;
try {
    while (true) {
        $written = @fwrite($fill, str_repeat('F', 65536));
        if ($written === false || $written === 0) {
            $observed = true;
            break;
        }
    }
} finally {
    fclose($fill);
}
if (! $observed) {
    throw new LogicException('Actual ENOSPC was not observed');
}
$denied = [];
try {
    rewind($input);
    $blobs->stage($input, 65536);
    throw new LogicException('Unexpected full-disk success');
} catch (ApiException $e) {
    $denied[] = $e->errorCode;
}
unlink('/fault/fill');
chmod($root, 0500);
try {
    rewind($input);
    $blobs->stage($input, 65536);
    throw new LogicException('Unexpected unavailable-store success');
} catch (ApiException $e) {
    $denied[] = $e->errorCode;
} finally {
    chmod($root, 0700);
}
try {
    app(DirectoryDurability::class)->sync('/proc');
    throw new LogicException('Unexpected unsupported-fsync success');
} catch (ApiException $e) {
    $denied[] = $e->errorCode;
}
if ($denied !== ['INSUFFICIENT_STORAGE', 'STORAGE_UNAVAILABLE', 'STORAGE_UNAVAILABLE'] || file_get_contents($blobs->path($valid['blob_id'])) !== $committed || DB::table('quota_ledgers')->orderBy('scope')->get()->toJson() !== $before) {
    throw new LogicException('Fault changed committed bytes/quota or returned an unexpected outcome');
}
rewind($input);
$recovered = $blobs->stage($input, 65536);
$blobs->verify((object) $recovered);
fclose($input);
echo json_encode(['status' => 'PASS', 'physical_tmpfs_bytes' => disk_total_space('/fault'), 'actual_enospc_observed' => $observed, 'typed_denials' => $denied, 'committed_bytes_preserved' => true, 'quota_unchanged' => true, 'real_directory_fsync_failure' => true, 'recovered_write_bytes' => $recovered['ciphertext_bytes']], JSON_THROW_ON_ERROR)."\n";
