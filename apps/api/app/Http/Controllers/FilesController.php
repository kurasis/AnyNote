<?php

namespace App\Http\Controllers;

use App\Auth\Contracts;
use App\Auth\Policy;
use App\Auth\RateLimits;
use App\Auth\Sessions;
use App\Crypto\PublicProtocol as P;
use App\Devices\Protocol as D;
use App\Files\Service;
use App\Http\ApiException;
use Illuminate\Http\Request;

final class FilesController
{
    public function __construct(private Contracts $contracts, private Sessions $sessions, private Service $files, private RateLimits $limits) {}

    public function __invoke(Request $r)
    {
        Policy::check();
        D::require($r->headers->has('Authorization') ? (! $r->headers->has('Origin') && ! $r->headers->has('Cookie')) : $r->header('Origin') === config('api.app_origin'), 'AUTH_REQUIRED');
        $session = $this->sessions->current($r);
        $secret = $this->sessions->secret($r);
        $op = $r->route()->getName();
        $this->limits->hit('p12-ip-'.$op, $r->ip(), 1200);
        $this->limits->hit('p12-session-'.$op, $session->id, 600);
        $id = $r->route('id') ?? $r->route('version');
        D::require($id === null || P::isBinary($id, 16), 'NOT_FOUND');
        $query = DevicesController::query($r, in_array($op, ['get_groups_id_files', 'get_me_unattached_files'], true) ? ['after'] : []);
        $after = $query['after'] ?? null;
        D::require($after === null || P::isBinary($after, 16), 'INVALID_REQUEST');
        $index = $r->route('index');
        D::require($index === null || (P::counter($index, '119')), 'NOT_FOUND');
        if ($r->isMethod('POST')) {
            $kind = $op === 'post_groups_id_uploads' ? 'reserve-request' : 'commit-request';
            $body = $r->attributes->get('anynote_control');
            D::require($body instanceof \stdClass, 'INVALID_REQUEST');
            $this->contracts->value('p12', $kind, $body);
        } elseif (! $r->isMethod('PUT')) {
            D::require($r->getContent() === '', 'INVALID_REQUEST');
        }
        if ($op === 'get_files_version_chunks_index') {
            [$handle, $bytes] = $this->files->download($secret, $id, (int) $index);
            // Only exact chunk requests. A partial AEAD frame cannot be authenticated.
            if ($r->headers->has('Range')) {
                fclose($handle);
                throw new ApiException('INVALID_REQUEST');
            }

            return response()->stream(function () use ($handle) {
                try {
                    while (! feof($handle)) {
                        $part = fread($handle, 65536);
                        if ($part === false) {
                            throw new ApiException('STORAGE_UNAVAILABLE');
                        }
                        echo $part;
                    }
                } finally {
                    fclose($handle);
                }
            }, 200, ['Content-Type' => 'application/octet-stream', 'Content-Length' => (string) $bytes, 'Content-Disposition' => 'attachment']);
        }
        $result = match ($op) {
            'post_groups_id_uploads' => $this->files->reserve($secret, $id, $body),
            'get_uploads_id' => $this->files->status($secret, $id),
            'put_uploads_id_parts_index' => $this->files->part($secret, $id, (int) $index, $r->getContent(true)),
            'post_uploads_id_commit' => $this->files->commit($secret, $id, $body->record),
            'delete_uploads_id' => $this->files->cancel($secret, $id),
            'get_files_version_manifest' => $this->files->manifest($secret, $id),
            'get_groups_id_files' => $this->files->listing($secret, $id, $after),
            'get_me_unattached_files' => $this->files->listing($secret, null, $after),
            'delete_files_version_unattached' => $this->files->deleteUnattached($secret, $id),
            'get_me_storage' => $this->files->storage($secret),
            default => throw new ApiException('NOT_FOUND'),
        };

        $shape = match ($op) {
            'post_groups_id_uploads','get_uploads_id','delete_uploads_id' => 'upload-status','post_uploads_id_commit' => 'receipt','put_uploads_id_parts_index' => null,'get_files_version_manifest' => 'manifest-result','get_groups_id_files','get_me_unattached_files' => 'files-page','get_me_storage' => 'storage','delete_files_version_unattached' => 'reclaim-result'
        };
        $value = json_decode(json_encode($result, JSON_THROW_ON_ERROR));
        if ($shape !== null) {
            $this->contracts->value('p12', $shape, $value);
        } else {
            D::require(P::counter($value->index, '119') && P::counter($value->ciphertext_bytes, '8388624') && P::isBinary($value->ciphertext_digest, 32), 'INVALID_CHUNK');
        }

        return response()->json($result);
    }
}
