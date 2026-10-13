<?php

namespace App\Jobs;

use App\Files\Service;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;

final class FilesCleanup implements ShouldQueue
{
    use Queueable;

    public int $tries = 3;

    public int $timeout = 120;

    public function handle(Service $files): void
    {
        $files->collect(50);
    }
}
