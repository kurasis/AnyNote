<?php

namespace App\Operations;

use App\Crypto\PublicProtocol as P;
use App\Devices\Protocol as D;
use App\Files\BlobStore;
use App\Files\DirectoryDurability;
use Illuminate\Support\Facades\DB;

/** Short, bounded hard-link custody bridges authorization and Nginx open/GC. */
final class Delivery
{
    private function root(): string
    {
        $path = Storage::privatePath('p16-delivery');
        D::require(is_dir($path) || mkdir($path, 0700, true), 'STORAGE_UNAVAILABLE');

        return $path;
    }

    public function ticket($authorizedHandle): string
    {
        $path = stream_get_meta_data($authorizedHandle)['uri'];
        $id = basename($path);
        D::require(P::isBinary($id, 16) && $path === app(BlobStore::class)->path($id), 'INVALID_REQUEST');
        $ticket = P::b64(random_bytes(16));
        $destination = $this->root().'/'.$ticket;
        $created = false;
        try {
            return DB::transaction(function () use ($path, $destination, $ticket, &$created) {
                DB::table('gc_coordination')->where('singleton', 1)->lockForUpdate()->first();
                D::require(DB::table('ciphertext_delivery_leases')->count() < 1000 && iterator_count(new \FilesystemIterator($this->root())) < 1000, 'RESOURCE_LIMIT');
                DB::table('ciphertext_delivery_leases')->insert(['id' => $ticket, 'expires_at' => now()->addHour()]);
                D::require(@link($path, $destination), 'STORAGE_UNAVAILABLE');
                $created = true;
                app(DirectoryDurability::class)->sync($this->root());

                return '/_anynote-cipher/'.$ticket;
            });
        } catch (\Throwable $error) {
            if ($created && is_file($destination)) {
                unlink($destination);
            }
            throw $error;
        }
    }

    public function collect(): int
    {
        return DB::transaction(function () {
            DB::table('gc_coordination')->where('singleton', 1)->lockForUpdate()->first();
            $count = 0;
            foreach (DB::table('ciphertext_delivery_leases')->where('expires_at', '<', now())->orderBy('id')->limit(100)->get() as $row) {
                $path = $this->root().'/'.$row->id;
                D::require(! is_file($path) || unlink($path), 'STORAGE_UNAVAILABLE');
                DB::table('ciphertext_delivery_leases')->where('id', $row->id)->delete();
                $count++;
            }
            foreach (new \DirectoryIterator($this->root()) as $entry) {
                if ($count >= 100) {
                    break;
                }
                if (! $entry->isDot() && ! $entry->isLink() && $entry->isFile() && P::isBinary($entry->getFilename(), 16) && $entry->getCTime() < time() - 3600 && ! DB::table('ciphertext_delivery_leases')->where('id', $entry->getFilename())->exists()) {
                    D::require(unlink($entry->getPathname()), 'STORAGE_UNAVAILABLE');
                    $count++;
                }
            }
            app(DirectoryDurability::class)->sync($this->root());

            return $count;
        });
    }
}
