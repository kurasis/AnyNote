<?php

use App\Crypto\PublicProtocol;
use App\Files\BlobStore;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\DB;

// Console-only inspection/control. No runtime endpoint or authentication shortcut.
require __DIR__.'/../../vendor/autoload.php';
$app = require __DIR__.'/../../bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();
set_exception_handler(function (Throwable $error): void {
    fwrite(STDERR, 'P17 controlled inspection failed: '.get_class($error).' at line '.$error->getLine()."\n");
    exit(1);
});
$db = DB::connection();
if (! $app->runningInConsole() || ! $app->environment('testing') || $db->getDatabaseName() !== 'anynote_p17_security' || ! hash_equals((string) $db->table('p17_test_owner')->value('owner'), (string) getenv('ANYNOTE_P17_TEST_OWNER'))) {
    throw new LogicException('Only owned P17 synthetic state is allowed');
}
$op = $argv[1] ?? '';
if ($op === 'invite') {
    $token = PublicProtocol::b64(random_bytes(32));
    $db->table('account_invites')->insert(['id' => PublicProtocol::b64(random_bytes(16)), 'creator_id' => null, 'bootstrap' => true, 'token_hash' => hash('sha256', $token), 'recipient_binding_hash' => null, 'status' => 'pending', 'expires_at' => now()->addHour()]);
    $value = ['token' => $token];
} elseif ($op === 'inspect') {
    $input = json_decode(stream_get_contents(STDIN), false, 32, JSON_THROW_ON_ERROR);
    if (! is_array($input->needles ?? null) || count($input->needles) < 5 || count($input->needles) > 100) {
        throw new LogicException('Bounded synthetic canaries required');
    }
    $needles = array_map(fn ($v) => base64_decode($v, true), $input->needles);
    foreach ($needles as $needle) {
        if (! is_string($needle) || strlen($needle) < 16 || strlen($needle) > 2048) {
            throw new LogicException('Invalid synthetic canary');
        }
    }
    $check = function (string $bytes) use ($needles): bool {
        foreach ($needles as $needle) {
            if (str_contains($bytes, $needle)) {
                return false;
            }
        }

        return true;
    };
    // A positive control must fail the same scanner before inspecting stores.
    if ($check('prefix'.$needles[0].'suffix')) {
        throw new LogicException('Canary scanner is ineffective');
    }
    $tables = $db->select('SHOW TABLES');
    $rows = 0;
    $bytes = 0;
    foreach ($tables as $table) {
        $name = array_values((array) $table)[0];
        foreach ($db->table($name)->cursor() as $row) {
            $rows++;
            foreach ((array) $row as $cell) {
                if ($cell === null) {
                    continue;
                }
                $cell = (string) $cell;
                $bytes += strlen($cell);
                if (strlen($cell) > 4194304 || ! $check($cell)) {
                    throw new LogicException('Synthetic SQL inspection failed; content omitted');
                }
            }
        }
    }
    $files = 0;
    foreach ([app(BlobStore::class)->root(), storage_path('logs')] as $directory) {
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS)) as $file) {
            if ($file->isLink() || ! $file->isFile() || $file->getSize() > 16777216) {
                throw new LogicException('Unbounded synthetic inspection target');
            }
            $data = file_get_contents($file->getPathname());
            $bytes += strlen($data);
            if (! $check($data)) {
                throw new LogicException('Synthetic file inspection failed; content omitted');
            }
            $files++;
        }
    }
    $counts = [];
    foreach ($input->operations ?? [] as $id) {
        if (! PublicProtocol::isBinary($id, 16)) {
            throw new LogicException('Invalid operation probe');
        }
        $counts[] = $db->table('object_revisions')->where('operation_id', $id)->count();
    }
    $value = ['status' => 'PASS', 'positive_canary_detected' => true, 'tables' => count($tables), 'rows' => $rows, 'files' => $files, 'bytes' => $bytes, 'canaries' => count($needles), 'operation_revision_counts' => $counts];
} else {
    throw new LogicException('Unsupported synthetic operation');
}
echo json_encode($value, JSON_THROW_ON_ERROR)."\n";
