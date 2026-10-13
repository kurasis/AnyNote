<?php

namespace App\Sync;

use App\Backend\Actor;
use App\Crypto\PublicProtocol as P;
use App\Devices\Protocol as D;
use App\Http\ApiException;
use App\Notes\Repository;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use stdClass;

/** Transport hints never replace independently verified content/security authority. */
final class Service
{
    public function __construct(private Repository $notes) {}

    private function scope(Actor $a, ?string $group): array
    {
        return ['service_id' => config('api.service_id'), 'account_id' => $a->accountId, 'root_fingerprint' => $a->rootFingerprint, 'group_id' => $group];
    }

    private function counter(): stdClass
    {
        $c = DB::table('sync_counters')->where('id', 1)->first();
        D::require($c !== null && P::counter((string) $c->sequence) && P::counter((string) $c->retained_from), 'SYNC_CURSOR_EXPIRED');

        return $c;
    }

    private function visible(Actor $a, stdClass $event, ?string $scope): bool
    {
        if ($event->audience_account_id !== null && $event->audience_account_id !== $a->accountId) {
            return false;
        }
        if ($event->group_id === null) {
            return $scope === null && $event->audience_account_id === $a->accountId;
        }
        if ($scope !== null && $event->group_id !== $scope) {
            return false;
        }
        try {
            $this->notes->group($a, $event->group_id);

            return true;
        } catch (ApiException $e) {
            if ($e->errorCode !== 'NOT_FOUND') {
                throw $e;
            }

            return false;
        }
    }

    public function delta(Request $r, stdClass $from, ?string $group, ?string $upper, int $limit, int $byteLimit): array
    {
        return DB::transaction(function () use ($r, $from, $group, $upper, $limit, $byteLimit) {
            $a = $this->notes->actor($r);
            if ($group !== null) {
                $this->notes->group($a, $group);
            }
            $c = $this->counter();
            D::require($from->generation === $c->generation && (int) $from->sequence >= (int) $c->retained_from && (int) $from->sequence <= (int) $c->sequence, 'SYNC_CURSOR_EXPIRED');
            $watermark = $upper ?? (string) $c->sequence;
            D::require(P::counter($watermark) && (int) $watermark >= (int) $from->sequence && (int) $watermark <= (int) $c->sequence, 'SYNC_CURSOR_EXPIRED');
            $rows = DB::table('sync_events')->where('sequence', '>', (int) $from->sequence)->where('sequence', '<=', (int) $watermark)->orderBy('sequence')->limit(1000)->get();
            $next = (int) $from->sequence;
            $events = [];
            $bytes = 512;
            $scanned = 0;
            foreach ($rows as $row) {
                D::require((int) $row->sequence === $next + 1, 'SYNC_CURSOR_EXPIRED');
                if ($this->visible($a, $row, $group)) {
                    $e = ['event_id' => $row->event_id, 'sequence' => (string) $row->sequence, 'group_id' => $row->group_id, 'kind' => $row->kind, 'object_id' => $row->object_id, 'revision_id' => $row->revision_id, 'digest' => $row->digest];
                    $size = strlen(P::canonical((object) $e)) + 1;
                    if (count($events) >= $limit || $bytes + $size > $byteLimit) {
                        break;
                    }
                    $events[] = $e;
                    $bytes += $size;
                }
                $next = (int) $row->sequence;
                $scanned++;
            }
            // Missing retained rows are not evidence that a watermark was scanned.
            D::require($rows->isNotEmpty() || $next === (int) $watermark, 'SYNC_CURSOR_EXPIRED');

            return ['version' => 1, 'scope' => $this->scope($a, $group), 'from_cursor' => (array) $from, 'next_cursor' => ['generation' => $c->generation, 'sequence' => (string) $next], 'watermark' => ['generation' => $c->generation, 'sequence' => $watermark], 'scanned_count' => (string) $scanned, 'events' => $events, 'complete' => $next === (int) $watermark];
        }, 3);
    }

    private function catalogHash(array $groups): string
    {
        $h = hash_init('sha256');
        hash_update($h, "AnyNote/P11/catalog\0".pack('N', count($groups)));
        foreach ($groups as $group) {
            $b = P::canonical((object) $group);
            hash_update($h, pack('N', strlen($b)).$b);
        }

        return P::b64(hash_final($h, true));
    }

    private function inventoryHash(array $pages, int $items): string
    {
        $h = hash_init('sha256');
        hash_update($h, "AnyNote/p02-v1/hash/snapshot-inventory\0".pack('N', count($pages)).pack('J', $items));
        foreach ($pages as $index => $page) {
            $bytes = P::canonical($page);
            hash_update($h, pack('N3', $index, count($page->items), strlen($bytes)).P::binary(P::digest('p02-v1', 'snapshot-page', $page)));
        }

        return P::b64(hash_final($h, true));
    }

    private function frozen(string $purpose): array
    {
        return ['contract' => 'p02-v1', 'protocol' => 'anynote', 'protocol_version' => 1, 'purpose' => $purpose];
    }

    private function release(stdClass $lease, string $state): void
    {
        DB::table('reference_pins')->where('snapshot_id', $lease->id)->delete();
        foreach (['snapshot_items', 'snapshot_pages', 'snapshot_catalog'] as $table) {
            DB::table($table)->where('snapshot_id', $lease->id)->delete();
        }
        DB::table('snapshot_sessions')->where('id', $lease->id)->update(['state' => $state]);
    }

    private function lease(Request $r, string $id): array
    {
        $a = $this->notes->actor($r);
        $l = DB::table('snapshot_sessions')->where('id', $id)->where('account_id', $a->accountId)->where('device_id', $a->deviceId)->lockForUpdate()->first();
        D::require($l !== null && $l->session_id === $a->sessionId && $l->root_fingerprint === $a->rootFingerprint, 'NOT_FOUND');
        D::require($l->state === 'active' && $l->expires_at > now()->format('Y-m-d H:i:s'), 'SYNC_CURSOR_EXPIRED');
        $c = $this->counter();
        D::require($l->transport_generation === $c->generation, 'SYNC_CURSOR_EXPIRED');

        return [$a, $l];
    }

    private function result(Actor $a, stdClass $lease): array
    {
        return ['version' => 1, 'scope' => $this->scope($a, $lease->scope_group_id), 'descriptor' => json_decode($lease->descriptor), 'catalog_count' => (string) $lease->catalog_count, 'catalog_digest' => $lease->catalog_digest];
    }

    public function start(Request $r, stdClass $body): array
    {
        return DB::transaction(function () use ($r, $body) {
            $a = $this->notes->actor($r);
            // Account/security locks precede the collector boundary; no counter lock.
            DB::table('gc_coordination')->where('singleton', 1)->lockForUpdate()->first();
            $request = P::digest('p11-sync', 'snapshot-request', $body);
            $old = DB::table('snapshot_sessions')->where('account_id', $a->accountId)->where('device_id', $a->deviceId)->where('operation_id', $body->operation_id)->lockForUpdate()->first();
            if ($old) {
                D::require($old->request_digest === $request, 'IDEMPOTENCY_MISMATCH');
                [$actor,$lease] = $this->lease($r, $old->id);

                return $this->result($actor, $lease);
            }
            foreach (DB::table('snapshot_sessions')->where('account_id', $a->accountId)->where('state', 'active')->where('expires_at', '<=', now())->lockForUpdate()->get() as $expired) {
                $this->release($expired, 'expired');
            }
            D::require(DB::table('snapshot_sessions')->where('account_id', $a->accountId)->where('state', 'active')->count() < 8, 'RESOURCE_LIMIT');
            $counter = $this->counter();
            $id = P::b64(random_bytes(16));
            $created = (int) floor(microtime(true) * 1000);
            $expires = $created + 1800000;
            $q = DB::table('groups')->whereIn('id', DB::table('group_memberships')->select('group_id')->where('account_id', $a->accountId)->where('status', 'active'))->whereIn('state', ['active', 'archived'])->orderBy('id');
            if ($body->group_id !== null) {
                $q->where('id', $body->group_id);
            }
            $groups = $q->limit(1001)->get();
            D::require($groups->count() <= 1000, 'RESOURCE_LIMIT');
            $catalog = [];
            $groupIds = [];
            foreach ($groups as $g) {
                $this->notes->group($a, $g->id);
                $catalog[] = $this->notes->status($a, $g);
                $groupIds[] = $g->id;
            }
            if ($body->group_id !== null) {
                D::require(count($groupIds) === 1, 'NOT_FOUND');
            }
            $rows = DB::table('object_revisions as r')->join('objects as o', 'r.object_id', '=', 'o.id')->join('object_key_wraps as w', 'r.revision_id', '=', 'w.revision_id')->whereIn('r.group_id', $groupIds)->orderBy('r.group_id')->orderByRaw('CAST(o.kind AS CHAR)')->orderBy('r.object_id')->orderBy('r.revision_id')->limit(50001)->get(['r.group_id', 'o.id', 'r.object_id', 'r.revision_id', 'r.envelope_digest', 'r.signed_envelope', 'r.ciphertext_bytes', 'w.wrap_record', 'o.kind', 'o.thread_id', 'o.archived', 'o.tombstoned', 'o.created_sequence', 'o.updated_sequence', DB::raw('OCTET_LENGTH(r.ciphertext) AS stored_bytes'), DB::raw('SHA2(r.ciphertext,256) AS stored_hash')]);
            D::require($rows->count() <= 50000, 'RESOURCE_LIMIT');
            $expected = DB::table('object_revisions')->whereIn('group_id', $groupIds)->count();
            D::require($rows->count() === $expected, 'INTEGRITY_FAILURE');
            $items = [];
            $records = [];
            foreach ($rows as $row) {
                $envelope = json_decode($row->signed_envelope);
                $context = $envelope->header->context;
                D::require((string) $row->stored_bytes === (string) $row->ciphertext_bytes && hash_equals(strtolower(bin2hex(P::binary($envelope->header->ciphertext_digest))), $row->stored_hash), 'CIPHERTEXT_MISMATCH');
                $item = (object) ['group_id' => $row->group_id, 'object_kind' => $row->kind, 'object_id' => $row->object_id, 'revision_id' => $row->revision_id, 'envelope_digest' => $row->envelope_digest, 'payload_status' => $context->action === 'soft-delete' ? 'tombstone' : 'retained'];
                $ref = $this->notes->reference($row);
                $items[] = $item;
                $records[] = [$row, $ref];
            }
            $pages = [];
            $part = [];
            $make = fn ($p, $n) => (object) [...$this->frozen('snapshot-page'), 'snapshot_id' => $id, 'page_index' => (string) $n, 'items' => $p];
            foreach ($items as $item) {
                $trial = $make([...$part, $item], count($pages));
                if ($part !== [] && (count($part) >= 500 || strlen(P::canonical($trial)) > 1048576)) {
                    $pages[] = $make($part, count($pages));
                    $part = [];
                }$part[] = $item;
            }
            if ($part !== []) {
                $pages[] = $make($part, count($pages));
            }
            $descriptor = (object) [...$this->frozen('snapshot-descriptor'), 'snapshot_id' => $id, 'account_id' => $a->accountId, 'device_id' => $a->deviceId, 'snapshot_purpose' => 'resync', 'watermark' => ['generation' => $counter->generation, 'sequence' => (string) $counter->sequence], 'created_at' => (string) $created, 'expires_at' => (string) $expires, 'page_count' => (string) count($pages), 'item_count' => (string) count($items), 'inventory_digest' => $this->inventoryHash($pages, count($items))];
            DB::table('snapshot_sessions')->insert(['id' => $id, 'account_id' => $a->accountId, 'device_id' => $a->deviceId, 'purpose' => 'resync', 'transport_generation' => $counter->generation, 'watermark' => $counter->sequence, 'created_at' => gmdate('Y-m-d H:i:s', (int) floor($created / 1000)), 'expires_at' => gmdate('Y-m-d H:i:s', (int) ceil($expires / 1000)), 'state' => 'active', 'session_id' => $a->sessionId, 'root_fingerprint' => $a->rootFingerprint, 'operation_id' => $body->operation_id, 'scope_group_id' => $body->group_id, 'request_digest' => $request, 'descriptor' => P::canonical($descriptor), 'catalog_count' => count($catalog), 'catalog_digest' => $this->catalogHash($catalog)]);
            foreach ($catalog as $n => $g) {
                DB::table('snapshot_catalog')->insert(['snapshot_id' => $id, 'group_id' => $g['group_id'], 'item_index' => $n, 'status_record' => P::canonical((object) $g)]);
            }
            foreach ($items as $n => $item) {
                [$row,$ref] = $records[$n];
                DB::table('snapshot_items')->insert(['id' => P::b64(random_bytes(16)), 'snapshot_id' => $id, 'group_id' => $item->group_id, 'revision_id' => $item->revision_id, 'item_index' => $n, 'inventory_record' => P::canonical((object) ['item' => $item, 'reference' => $ref])]);
                DB::table('reference_pins')->insert(['id' => P::b64(random_bytes(16)), 'snapshot_id' => $id, 'group_id' => $item->group_id, 'revision_id' => $item->revision_id]);
            }
            foreach ($pages as $n => $page) {
                DB::table('snapshot_pages')->insert(['snapshot_id' => $id, 'page_index' => $n, 'page_record' => P::canonical($page)]);
            }
            $lease = DB::table('snapshot_sessions')->where('id', $id)->first();

            return $this->result($a, $lease);
        }, 3);
    }

    public function catalog(Request $r, string $id, int $start): array
    {
        return DB::transaction(function () use ($r, $id, $start) {
            [$a,$l] = $this->lease($r, $id);
            D::require($start <= (int) $l->catalog_count, 'NOT_FOUND');
            $rows = DB::table('snapshot_catalog')->where('snapshot_id', $id)->where('item_index', '>=', $start)->orderBy('item_index')->limit(20)->get();
            $groups = [];
            $bytes = 256;
            foreach ($rows as $row) {
                $this->notes->group($a, $row->group_id);
                $size = strlen($row->status_record) + 1;
                if ($groups !== [] && $bytes + $size > 1048576) {
                    break;
                }D::require($bytes + $size <= 1048576, 'RESOURCE_LIMIT');
                $groups[] = json_decode($row->status_record);
                $bytes += $size;
            }
            $next = $start + count($groups);

            return ['version' => 1, 'snapshot_id' => $id, 'start' => (string) $start, 'groups' => $groups, 'next' => $next < (int) $l->catalog_count ? (string) $next : null];
        }, 3);
    }

    public function page(Request $r, string $id, int $index): array
    {
        return DB::transaction(function () use ($r, $id, $index) {
            [$a,$l] = $this->lease($r, $id);
            $p = DB::table('snapshot_pages')->where('snapshot_id', $id)->where('page_index', $index)->first();
            D::require($p !== null, 'NOT_FOUND');
            $page = json_decode($p->page_record);
            foreach (array_unique(array_map(fn ($x) => $x->group_id, $page->items)) as $group) {
                $this->notes->group($a, $group);
            }

            return ['version' => 1, 'scope' => $this->scope($a, $l->scope_group_id), 'page' => $page];
        }, 3);
    }

    public function bundle(Request $r, string $id, string $revision): array
    {
        return DB::transaction(function () use ($r, $id, $revision) {
            [$a,$l] = $this->lease($r, $id);
            $stored = DB::table('snapshot_items')->where('snapshot_id', $id)->where('revision_id', $revision)->first();
            D::require($stored !== null, 'NOT_FOUND');
            $v = json_decode($stored->inventory_record);
            $this->notes->group($a, $stored->group_id);
            D::require(DB::table('reference_pins')->where('snapshot_id', $id)->where('revision_id', $revision)->exists(), 'INTEGRITY_FAILURE');
            $result = $this->notes->bundle($r, $v->item->object_id, $revision);
            D::require(P::digest('p02-v1', 'envelope', $result['bundle']['envelope']) === $v->item->envelope_digest, 'INTEGRITY_FAILURE');

            return ['version' => 1, 'snapshot_id' => $id, 'item' => $v->item, 'bundle' => $result['bundle'], 'reference' => $v->reference];
        }, 3);
    }

    public function renew(Request $r, string $id): array
    {
        // Resync has a fixed immutable <=30 minute lease; renew reauthorizes it.
        // A new snapshot is required after expiry. Export renewal remains P13.
        return DB::transaction(function () use ($r, $id) {
            [$a,$l] = $this->lease($r, $id);
            foreach (DB::table('snapshot_catalog')->where('snapshot_id', $id)->get() as $g) {
                $this->notes->group($a, $g->group_id);
            }

            return $this->result($a, $l);
        }, 3);
    }

    public function cancel(Request $r, string $id): array
    {
        return DB::transaction(function () use ($r, $id) {
            $a = $this->notes->actor($r);
            DB::table('gc_coordination')->where('singleton', 1)->lockForUpdate()->first();
            $l = DB::table('snapshot_sessions')->where('id', $id)->where('account_id', $a->accountId)->where('device_id', $a->deviceId)->where('session_id', $a->sessionId)->lockForUpdate()->first();
            D::require($l !== null && $l->root_fingerprint === $a->rootFingerprint, 'NOT_FOUND');
            $this->release($l, 'cancelled');

            return ['version' => 1, 'snapshot_id' => $id, 'state' => 'CANCELLED'];
        }, 3);
    }

    public function ack(Request $r, stdClass $body): array
    {
        return DB::transaction(function () use ($r, $body) {
            $a = $this->notes->actor($r);
            $c = $this->counter();
            D::require($body->cursor->generation === $c->generation && (int) $body->cursor->sequence <= (int) $c->sequence, 'SYNC_CURSOR_EXPIRED');
            if ($body->group_id !== null) {
                $this->notes->group($a, $body->group_id);
            }$scope = $body->group_id ?? $a->accountId;
            $q = DB::table('sync_acknowledgements')->where('account_id', $a->accountId)->where('device_id', $a->deviceId)->where('scope_id', $scope);
            $old = $q->lockForUpdate()->first();
            D::require(! $old || $old->generation !== $c->generation || (int) $body->cursor->sequence >= (int) $old->sequence, 'SYNC_CURSOR_EXPIRED');
            $data = ['generation' => $c->generation, 'sequence' => $body->cursor->sequence];
            if ($old) {
                $q->update($data);
            } else {
                DB::table('sync_acknowledgements')->insert(['account_id' => $a->accountId, 'device_id' => $a->deviceId, 'scope_id' => $scope, ...$data]);
            }

            return ['version' => 1, 'cursor' => $body->cursor, 'state' => 'ACKNOWLEDGED'];
        }, 3);
    }
}
