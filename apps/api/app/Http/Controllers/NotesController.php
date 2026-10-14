<?php

namespace App\Http\Controllers;

use App\Auth\Contracts;
use App\Auth\Policy;
use App\Auth\RateLimits;
use App\Auth\Sessions;
use App\Backend\ObjectService;
use App\Backend\ScopedRepository;
use App\Crypto\PublicProtocol as P;
use App\Devices\Protocol;
use App\Http\ApiException;
use App\Notes\Repository;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

final class NotesController
{
    public function __construct(private Contracts $contracts, private Sessions $sessions, private RateLimits $limits, private Repository $repository) {}

    public function __invoke(Request $r)
    {
        Policy::check();
        if ($r->headers->has('Authorization') ? ($r->headers->has('Origin') || $r->headers->has('Cookie')) : $r->header('Origin') !== config('api.app_origin')) {
            throw new ApiException('AUTH_REQUIRED');
        }
        $op = $r->route()->getName();
        $id = $r->route('id');
        $revision = $r->route('revision');
        foreach ([$id, $revision] as $value) {
            if ($value !== null && ! P::isBinary($value, 16)) {
                throw new ApiException('NOT_FOUND');
            }
        }
        $this->limits->hit('p09-ip-'.$op, $r->ip(), $r->isMethod('GET') ? 180 : 120);
        $session = $this->sessions->current($r);
        $this->limits->hit('p09-session-'.$op, $session->id, $r->isMethod('GET') ? 120 : 60);
        if ($r->isMethod('POST')) {
            Protocol::require($r->getQueryString() === null && $r->attributes->get('anynote_control') instanceof \stdClass, 'INVALID_REQUEST');
            $kind = $op === 'post_groups' ? 'group-create' : 'commit-request';
            $body = $this->contracts->value('p09', $kind, $r->attributes->get('anynote_control'));
            if ($op === 'post_groups') {
                $result = $this->repository->create($r, $body);
                $shape = 'group-status';
            } else {
                $result = $this->commit($r, $body, $id, $op);
                $shape = 'receipt-result';
            }
        } else {
            Protocol::require($r->getContent() === '', 'INVALID_REQUEST');
            $paginated = in_array($op, ['get_groups', 'get_groups_id_threads', 'get_groups_id_trash', 'get_threads_id_entries', 'get_objects_id_revisions'], true);
            $q = DevicesController::query($r, $paginated ? ['after'] : []);
            $after = $q['after'] ?? null;
            Protocol::require($after === null || ($op === 'get_threads_id_entries' ? P::counter($after) : P::isBinary($after, 16)), 'INVALID_REQUEST');
            [$result, $shape] = match ($op) {
                'get_groups' => [$this->repository->groups($r, $after), 'groups-page'],
                'get_groups_id' => [$this->repository->one($r, $id), 'group-status'],
                'get_groups_id_threads' => [$this->repository->objects($r, $id, 'threads', $after), 'objects-page'],
                'get_groups_id_trash' => [$this->repository->objects($r, $id, 'trash', $after), 'objects-page'],
                'get_threads_id_entries' => [$this->repository->objects($r, $id, 'entries', $after), 'objects-page'],
                'get_objects_id' => [$this->repository->state($r, $id), 'object-state'],
                'get_objects_id_revisions' => [$this->repository->revisions($r, $id, $after), 'revisions-page'],
                'get_objects_id_revisions_revision' => [$this->repository->bundle($r, $id, $revision), 'bundle-result'],
                'get_me_content_receipts_id' => [app(ScopedRepository::class)->receipt($this->sessions->secret($r), $id), 'receipt-result'],
                default => throw new ApiException('NOT_FOUND'),
            };
        }
        Protocol::require(strlen(json_encode($result, JSON_THROW_ON_ERROR)) <= ($shape === 'bundle-result' ? 4194304 : 1048576), 'RESOURCE_LIMIT');
        $this->contracts->value('p09', $shape, json_decode(json_encode($result, JSON_THROW_ON_ERROR)));

        return response()->json($result);
    }

    private function commit(Request $r, \stdClass $body, string $id, string $op): array
    {
        return DB::transaction(function () use ($r, $body, $id, $op) {
            $a = $this->repository->actor($r);
            DB::table('gc_coordination')->where('singleton', 1)->lockForUpdate()->first();
            $this->repository->group($a, $body->group_id);
            if ($op === 'post_groups_id_threads') {
                Protocol::require($body->group_id === $id && $body->object_kind === 'thread' && $body->thread_id === null && $body->action === 'create', 'MALFORMED_ENVELOPE');
            } elseif ($op === 'post_threads_id_entries') {
                $thread = $this->repository->object($a, $id);
                Protocol::require($thread->kind === 'thread' && $thread->group_id === $body->group_id && $body->thread_id === $id && $body->object_kind === 'entry' && $body->action === 'create', 'MALFORMED_ENVELOPE');
            } else {
                Protocol::require($body->object_id === $id, 'MALFORMED_ENVELOPE');
                $action = match ($op) {
                    'post_objects_id_tombstone' => 'soft-delete', 'post_objects_id_restore' => 'restore', default => null
                };
                Protocol::require($action === null ? in_array($body->action, ['create', 'update'], true) : $body->action === $action, 'MALFORMED_ENVELOPE');
                if ($body->action === 'create') {
                    Protocol::require($body->object_kind === 'group-metadata' && $body->object_id === $body->group_id, 'MALFORMED_ENVELOPE');
                } else {
                    $o = $this->repository->object($a, $id);
                    Protocol::require($o->group_id === $body->group_id && $o->kind === $body->object_kind && $o->thread_id === $body->thread_id, 'MALFORMED_ENVELOPE');
                }
            }

            // Reuse the real P04 authorization/CAS/quota/receipt/counter-last transaction.
            return app(ObjectService::class)->commit($this->sessions->secret($r), P::canonical($body));
        }, 3);
    }
}
