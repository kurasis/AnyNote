<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use RuntimeException;

final class FoundationCheck extends Command
{
    protected $signature = 'foundation:check';

    protected $description = 'Verify disposable MariaDB transactions without product tables';

    public function handle(): int
    {
        if (! app()->environment(['local', 'testing'])) {
            $this->error('Foundation checks require local or testing environment.');

            return self::FAILURE;
        }

        $db = DB::connection();
        $version = $db->selectOne('SELECT VERSION() AS version')->version;
        if (! str_contains($version, 'MariaDB')) {
            throw new RuntimeException('Foundation checks require MariaDB.');
        }

        // This name is connection-local. No persistent schema or migration is added.
        $db->statement('CREATE TEMPORARY TABLE anynote_foundation_probe (id INT PRIMARY KEY, value INT NOT NULL) ENGINE=InnoDB');
        try {
            $db->transaction(fn () => $db->insert('INSERT INTO anynote_foundation_probe VALUES (1, 17)'));
            try {
                $db->transaction(function () use ($db): void {
                    $db->update('UPDATE anynote_foundation_probe SET value = 99 WHERE id = 1');
                    throw new RuntimeException('synthetic rollback');
                });
            } catch (RuntimeException $e) {
                if ($e->getMessage() !== 'synthetic rollback') {
                    throw $e;
                }
            }
            if ((int) $db->selectOne('SELECT value FROM anynote_foundation_probe WHERE id = 1')->value !== 17) {
                throw new RuntimeException('Rollback did not preserve committed value.');
            }
        } finally {
            $db->statement('DROP TEMPORARY TABLE anynote_foundation_probe');
        }

        $this->line(json_encode(['status' => 'PASS', 'database' => $version, 'commit' => true, 'rollback' => true, 'temporary_table_cleanup' => true], JSON_THROW_ON_ERROR));

        return self::SUCCESS;
    }
}
