<?php

namespace App\Files;

use App\Devices\Protocol as D;

/** Strict production directory durability; Windows CI supplies an actual OS flush adapter. */
class DirectoryDurability
{
    public function sync(string $path): void
    {
        $directory = fopen($path, 'r');
        D::require($directory !== false, 'STORAGE_UNAVAILABLE');
        try {
            D::require(fsync($directory), 'STORAGE_UNAVAILABLE');
        } finally {
            fclose($directory);
        }
    }
}
