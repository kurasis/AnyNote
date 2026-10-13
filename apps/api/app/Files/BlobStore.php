<?php

namespace App\Files;

use App\Crypto\PublicProtocol as P;
use App\Devices\Protocol as D;
use App\Http\ApiException;
use Illuminate\Support\Facades\DB;

/** Private ciphertext-only immutable store. No user-controlled path components. */
final class BlobStore
{
    public function root(): string
    {
        $root = storage_path('app/private/p12-blobs');
        if (! is_dir($root) && ! mkdir($root, 0700, true) && ! is_dir($root)) {
            throw new ApiException('STORAGE_UNAVAILABLE');
        }

        return $root;
    }

    public function path(string $id): string
    {
        D::require(P::isBinary($id, 16), 'NOT_FOUND');

        return $this->root().'/'.$id;
    }

    public function capacity(int $bytes): void
    {
        $available = disk_free_space($this->root());
        D::require($available !== false && $available >= $bytes + 268435456, 'INSUFFICIENT_STORAGE');
    }

    /** Bounded copy; measured received bytes are authoritative, including chunked HTTP. */
    public function stage($input, int $expected): array
    {
        D::require(is_resource($input) && $expected >= 16 && $expected <= 8388624, 'INVALID_REQUEST');
        $this->capacity($expected);
        $id = P::b64(random_bytes(16));
        $path = $this->path($id);
        $out = fopen($path, 'xb');
        if ($out === false) {
            throw new ApiException('STORAGE_UNAVAILABLE');
        }
        chmod($path, 0600);
        $hash = hash_init('sha256');
        $size = 0;
        try {
            while (! feof($input)) {
                $part = fread($input, 65536);
                D::require($part !== false, 'STORAGE_UNAVAILABLE');
                $size += strlen($part);
                D::require($size <= $expected, 'INTEGRITY_FAILURE');
                hash_update($hash, $part);
                $offset = 0;
                while ($offset < strlen($part)) {
                    $written = fwrite($out, substr($part, $offset));
                    D::require($written !== false && $written > 0, 'STORAGE_UNAVAILABLE');
                    $offset += $written;
                }
            }
            D::require($size === $expected, 'INTEGRITY_FAILURE');
            D::require(fflush($out) && fsync($out), 'STORAGE_UNAVAILABLE');
            fclose($out);
            $out = null;
            $this->syncDirectory();

            return ['blob_id' => $id, 'ciphertext_bytes' => $size, 'digest' => P::b64(hash_final($hash, true))];
        } catch (\Throwable $e) {
            if (is_resource($out)) {
                fclose($out);
            }
            unlink($path);
            throw $e;
        }
    }

    public function verify(object $part): void
    {
        $path = $this->path($part->blob_id);
        D::require(is_file($path) && filesize($path) === (int) $part->ciphertext_bytes && P::b64(hash_file('sha256', $path, true)) === $part->digest, 'INTEGRITY_FAILURE');
    }

    /** Only old unreferenced opaque files in this private adapter's own namespace. */
    public function orphans(int $limit = 100): int
    {
        $removed = 0;
        $cursor = DB::table('gc_coordination')->where('singleton', 1)->value('last_blob_scan');
        $candidates = [];
        $directory = opendir($this->root());
        D::require($directory !== false, 'STORAGE_UNAVAILABLE');
        try {
            while (($id = readdir($directory)) !== false) {
                if (! P::isBinary($id, 16) || ($cursor !== null && strcmp($id, $cursor) <= 0)) {
                    continue;
                }
                $candidates[] = $id;
                sort($candidates, SORT_STRING);
                if (count($candidates) > $limit) {
                    array_pop($candidates);
                }
            }
        } finally {
            closedir($directory);
        }
        foreach ($candidates as $id) {
            $path = $this->path($id);
            if (! is_link($path) && is_file($path) && filemtime($path) < time() - 259200 && ! DB::table('upload_parts')->where('blob_id', $id)->exists() && ! DB::table('file_chunks')->where('blob_id', $id)->exists()) {
                $this->remove($id);
                $removed++;
            }
        }
        DB::table('gc_coordination')->where('singleton', 1)->update(['last_blob_scan' => count($candidates) === $limit ? end($candidates) : null]);

        return $removed;
    }

    public function remove(string $id): void
    {
        $path = $this->path($id);
        D::require(! is_file($path) || unlink($path), 'STORAGE_UNAVAILABLE');
        $this->syncDirectory();
    }

    private function syncDirectory(): void
    {
        $directory = fopen($this->root(), 'r');
        D::require($directory !== false, 'STORAGE_UNAVAILABLE');
        try {
            D::require(fsync($directory), 'STORAGE_UNAVAILABLE');
        } finally {
            fclose($directory);
        }
    }
}
