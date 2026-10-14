<?php

namespace App\Http\Controllers;

use App\Auth\Contracts;
use App\Auth\Policy;
use App\Auth\RateLimits;
use App\Auth\Sessions;
use App\Content\Exports;
use App\Content\Retainer;
use App\Content\Thumbnails;
use App\Crypto\PublicProtocol as P;
use App\Devices\Protocol as D;
use App\Http\ApiException;
use Illuminate\Http\Request;

final class ContentController
{
    public function __construct(private Contracts $contracts, private Sessions $sessions, private Exports $exports, private RateLimits $limits) {}

    public function __invoke(Request $r)
    {
        Policy::check();
        D::require($r->headers->has('Authorization') ? (! $r->headers->has('Origin') && ! $r->headers->has('Cookie')) : $r->header('Origin') === config('api.app_origin'), 'AUTH_REQUIRED');
        $session = $this->sessions->current($r);
        $op = $r->route()->getName();
        $this->limits->hit('p13-ip-'.$op, $r->ip(), 1200);
        $this->limits->hit('p13-session-'.$op, $session->id, 600);
        $id = $r->route('id');
        $revision = $r->route('revision');
        $index = $r->route('index');
        foreach ([$id, $revision] as $value) {
            D::require($value === null || P::isBinary($value, 16), 'NOT_FOUND');
        }
        D::require($index === null || P::counter($index, '119'), 'NOT_FOUND');
        $query = DevicesController::query($r, in_array($op, ['get_exports_id_catalog', 'get_exports_id_pages', 'get_exports_id_headers'], true) ? ['start'] : ($op === 'get_groups_id_retention' ? ['after'] : []));
        D::require(! isset($query['start']) || P::counter($query['start'], '51000'), 'INVALID_REQUEST');
        D::require(! isset($query['after']) || P::isBinary($query['after'], 16), 'INVALID_REQUEST');
        $start = (int) ($query['start'] ?? '0');
        if ($r->isMethod('POST')) {
            $body = $r->attributes->get('anynote_control');
            D::require($body instanceof \stdClass, 'INVALID_REQUEST');
            $this->contracts->value('p13', match ($op) {
                'post_exports' => 'export-request', 'post_files_revision_thumbnail' => 'thumbnail-link', 'post_groups_id_retention' => 'retention-request', 'post_revisions_revision_retention_pin' => 'retention-pin-request', default => 'renew-request'
            }, $body);
        } else {
            D::require($r->getContent() === '', 'INVALID_REQUEST');
        }
        if (in_array($op, ['get_groups_id_retention', 'post_groups_id_retention', 'post_revisions_revision_retention_pin'], true)) {
            $result = $op === 'post_revisions_revision_retention_pin' ? app(Retainer::class)->pin($r, $revision, $body->pinned) : app(Retainer::class)->request($r, $id, $r->isMethod('POST'), $r->isMethod('POST') ? $body->after : ($query['after'] ?? null));
            $this->contracts->value('p13', $op === 'post_revisions_revision_retention_pin' ? 'retention-pin-result' : 'retention-result', json_decode(json_encode($result, JSON_THROW_ON_ERROR)));

            return response()->json($result);
        }
        if ($op === 'post_files_revision_thumbnail') {
            $result = app(Thumbnails::class)->link($r, $revision, $body);
            $this->contracts->value('p13', 'thumbnail-result', json_decode(json_encode($result, JSON_THROW_ON_ERROR)));

            return response()->json($result);
        }
        if ($op === 'get_exports_id_files_revision_chunks_index') {
            D::require(! $r->headers->has('Range'), 'INVALID_REQUEST');
            [$handle, $bytes] = $this->exports->chunk($r, $id, $revision, (int) $index);

            return response()->stream(function () use ($handle) {
                try {
                    while (! feof($handle)) {
                        $part = fread($handle, 65536);
                        if ($part === false) {
                            throw new ApiException('TEMPORARY_UNAVAILABLE');
                        } echo $part;
                    }
                } finally {
                    fclose($handle);
                }
            }, 200, ['Content-Type' => 'application/octet-stream', 'Content-Length' => (string) $bytes, 'Content-Disposition' => 'attachment']);
        }
        $result = match ($op) {
            'post_exports' => $this->exports->start($r, $body), 'get_exports_id' => $this->exports->status($r, $id),
            'post_exports_id_renew' => $this->exports->renew($r, $id), 'delete_exports_id' => $this->exports->cancel($r, $id),
            'get_exports_id_catalog' => $this->exports->catalog($r, $id, $start), 'get_exports_id_pages' => $this->exports->page($r, $id, $start),
            'get_exports_id_headers' => $this->exports->headers($r, $id, $start),
            'get_exports_id_records_revision' => $this->exports->record($r, $id, $revision), default => throw new ApiException('NOT_FOUND'),
        };
        $kind = match ($op) {
            'post_exports','get_exports_id','post_exports_id_renew' => 'export-result','delete_exports_id' => 'cancel-result','get_exports_id_catalog' => 'catalog-page','get_exports_id_pages' => 'export-page-result','get_exports_id_records_revision' => 'export-record-result', 'get_exports_id_headers' => 'export-header-page'
        };
        $this->contracts->value('p13', $kind, json_decode(json_encode($result, JSON_THROW_ON_ERROR)));

        return response()->json($result);
    }
}
