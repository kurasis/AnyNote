<?php

namespace Tests\Support;

use App\Devices\Protocol as D;
use App\Files\DirectoryDurability;
use Illuminate\Support\Facades\DB;
use Symfony\Component\Process\Process;

/** Real Windows synthetic-runner durability, never a production storage fallback. */
final class P14WindowsDurability extends DirectoryDurability
{
    public function sync(string $path): void
    {
        D::require(PHP_OS_FAMILY === 'Windows' && app()->environment('testing') && getenv('GITHUB_ACTIONS') === 'true', 'STORAGE_UNAVAILABLE');
        D::require(config('database.connections.mariadb.database') === 'anynote_p06_tests' && preg_match('/^[a-f0-9]{64}$/D', (string) getenv('ANYNOTE_P06_TEST_OWNER')) === 1 && hash_equals((string) DB::table('p06_test_owner')->value('owner'), (string) getenv('ANYNOTE_P06_TEST_OWNER')), 'STORAGE_UNAVAILABLE');
        D::require($path === storage_path('app/private/p12-blobs'), 'STORAGE_UNAVAILABLE');
        $root = dirname(base_path(), 2);
        $helper = $root.'/.local/p14-tools/flush-volume.exe';
        $pin = $root.'/.local/p14-tools/flush-volume.sha256';
        D::require(is_file($helper) && is_file($pin) && hash_equals(trim(file_get_contents($pin)), hash_file('sha256', $helper)), 'STORAGE_UNAVAILABLE');
        // Opening/flushing a volume requires the hosted runner's administration rights.
        // No write, format, dismount or arbitrary argument is exposed by this helper.
        $process = new Process([$helper], $root);
        $process->setTimeout(30);
        $process->run();
        D::require($process->isSuccessful(), 'STORAGE_UNAVAILABLE');
        $result = json_decode($process->getOutput(), true, 8, JSON_THROW_ON_ERROR);
        D::require(($result['status'] ?? null) === 'PASS' && ($result['primitive'] ?? null) === 'Windows FlushFileBuffers volume', 'STORAGE_UNAVAILABLE');
    }
}
