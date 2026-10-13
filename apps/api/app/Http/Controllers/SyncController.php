<?php

namespace App\Http\Controllers;

use App\Auth\Contracts;
use App\Auth\Policy;
use App\Auth\RateLimits;
use App\Auth\Sessions;
use App\Backend\ScopedRepository;
use App\Crypto\PublicProtocol as P;
use App\Devices\Protocol as D;
use App\Http\ApiException;
use App\Sync\Service;
use Illuminate\Http\Request;

final class SyncController
{
    public function __construct(private Contracts $contracts, private Sessions $sessions, private RateLimits $limits, private Service $service) {}

    private function query(Request $r, array $allowed): array
    {
        $raw = (string) $r->server->get('QUERY_STRING', '');
        D::require(strlen($raw) <= 2048, 'INVALID_REQUEST');
        $out = [];
        if ($raw === '') {
            return $out;
        }
        foreach (explode('&', $raw) as $part) {
            $bits = explode('=', $part);
            D::require(count($bits) === 2 && in_array($bits[0], $allowed, true) && ! array_key_exists($bits[0], $out) && preg_match('/^[A-Za-z0-9_-]+$/D', $bits[1]), 'INVALID_REQUEST');
            $out[$bits[0]] = $bits[1];
        }

        return $out;
    }

    public function __invoke(Request $r)
    {
        Policy::check();
        if ($r->headers->has('Authorization') ? ($r->headers->has('Origin') || $r->headers->has('Cookie')) : $r->header('Origin') !== config('api.app_origin')) {
            throw new ApiException('AUTH_REQUIRED');
        }
        $s = $this->sessions->current($r);
        $op = $r->route()->getName();
        $this->limits->hit('p11-ip-'.$op, $r->ip(), $r->isMethod('GET') ? 1200 : 120);
        $this->limits->hit('p11-session-'.$op, $s->id, $r->isMethod('GET') ? 600 : 60);
        $id = $r->route('id');
        $revision = $r->route('revision');
        $operation = $r->route('operation_id');
        foreach ([$id, $revision, $operation] as $value) {
            D::require($value === null || P::isBinary($value, 16), 'NOT_FOUND');
        }
        if ($r->isMethod('GET')) {
            D::require($r->getContent() === '', 'INVALID_REQUEST');
            $q = $this->query($r, $op === 'get_sync' ? ['generation', 'sequence', 'watermark', 'group', 'limit', 'bytes'] : ($op === 'get_snapshots_id_pages' ? ['index'] : (in_array($op, ['get_snapshots_id_catalog', 'get_snapshots_id_files'], true) ? ['start'] : [])));
            if ($op === 'get_sync') {
                D::require(isset($q['generation'],$q['sequence']) && P::isBinary($q['generation'], 16) && P::counter($q['sequence']), 'INVALID_REQUEST');
                foreach (['watermark', 'limit', 'bytes'] as $key) {
                    D::require(! isset($q[$key]) || P::counter($q[$key]), 'INVALID_REQUEST');
                }
                D::require(! isset($q['group']) || P::isBinary($q['group'], 16), 'INVALID_REQUEST');
                $limit = (int) ($q['limit'] ?? '200');
                $bytes = (int) ($q['bytes'] ?? '1048576');
                D::require($limit >= 1 && $limit <= 1000 && $bytes >= 1024 && $bytes <= 1048576, 'INVALID_REQUEST');
                $result = $this->service->delta($r, (object) ['generation' => $q['generation'], 'sequence' => $q['sequence']], $q['group'] ?? null, $q['watermark'] ?? null, $limit, $bytes);
                $shape = 'delta-page';
            } elseif ($op === 'get_snapshots_id_pages') {
                D::require(isset($q['index']) && P::counter($q['index']) && (int) $q['index'] < 8000, 'INVALID_REQUEST');
                $result = $this->service->page($r, $id, (int) $q['index']);
                $shape = 'snapshot-page-result';
            } elseif ($op === 'get_snapshots_id_catalog') {
                D::require(! isset($q['start']) || P::counter($q['start']) && (int) $q['start'] <= 1000, 'INVALID_REQUEST');
                $result = $this->service->catalog($r, $id, (int) ($q['start'] ?? '0'));
                $shape = 'catalog-page';
            } elseif ($op === 'get_snapshots_id_revisions_revision') {
                $result = $this->service->bundle($r, $id, $revision);
                $shape = 'snapshot-bundle';
            } elseif ($op === 'get_snapshots_id_files') {
                D::require(! isset($q['start']) || P::counter($q['start'], '1000'), 'INVALID_REQUEST');

                return response()->json($this->service->files($r, $id, (int) ($q['start'] ?? '0')));
            } elseif ($op === 'get_mutations_operation_id') {
                $result = app(ScopedRepository::class)->receipt($this->sessions->secret($r), $operation);
                $this->contracts->value('p09', 'receipt-result', json_decode(json_encode($result, JSON_THROW_ON_ERROR)));

                return response()->json($result);
            } else {
                throw new ApiException('NOT_FOUND');
            }
        } elseif ($r->isMethod('DELETE')) {
            D::require($r->getQueryString() === null && $r->getContent() === '', 'INVALID_REQUEST');
            $result = $this->service->cancel($r, $id);
            $shape = 'cancel-result';
        } else {
            D::require($r->getQueryString() === null && $r->attributes->get('anynote_control') instanceof \stdClass, 'INVALID_REQUEST');
            if ($op === 'post_sync_ack') {
                $body = $this->contracts->value('p11', 'ack-request', $r->attributes->get('anynote_control'));
                $result = $this->service->ack($r, $body);
                $shape = 'ack-result';
            } elseif ($op === 'post_snapshots_id_renew') {
                $this->contracts->value('p11', 'renew-request', $r->attributes->get('anynote_control'));
                $result = $this->service->renew($r, $id);
                $shape = 'snapshot-result';
            } else {
                $body = $this->contracts->value('p11', 'snapshot-request', $r->attributes->get('anynote_control'));
                D::require($op === 'post_snapshots' || $op === 'post_groups_id_snapshots' && $body->group_id === $id, 'INVALID_REQUEST');
                $result = $this->service->start($r, $body);
                $shape = 'snapshot-result';
            }
        }
        D::require(strlen(json_encode($result, JSON_THROW_ON_ERROR)) <= ($shape === 'snapshot-bundle' ? 4194304 : 1048576), 'RESOURCE_LIMIT');
        $this->contracts->value('p11', $shape, json_decode(json_encode($result, JSON_THROW_ON_ERROR)));

        return response()->json($result);
    }
}
