<?php

namespace App\Operations;

/** Separate disposable SQL fixtures must never collect another database's blobs. */
final class Storage
{
    public static function privatePath(string $name): string
    {
        $database = (string) config('database.connections.mariadb.database');
        if (app()->environment(['local', 'testing']) && $database !== 'anynote_p06_tests') {
            return storage_path('framework/testing/isolated-'.hash('sha256', $database).'/private/'.$name);
        }

        // Preserve the established P06/native Windows fixture path and all
        // ordinary single-database production storage without moving any data.
        return storage_path('app/private/'.$name);
    }
}
