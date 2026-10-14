<?php

namespace App\Content;

use App\Auth\Sessions;
use App\Backend\Actor;
use App\Crypto\PublicProtocol as P;
use App\Devices\Protocol as D;
use App\Files\Service as Files;
use App\Notes\Repository;
use App\Sync\Service as Snapshots;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use stdClass;

/** A captured inventory is a pin, never a substitute for current authorization. */
final class Exports
{
    public function __construct(private Repository $notes, private Snapshots $snapshots, private Files $files) {}

    private function current(Request $r, string $id): array
    {
        $actor = $this->notes->actor($r);
        DB::table('gc_coordination')->where('singleton', 1)->lockForUpdate()->first();
        $lease = DB::table('snapshot_sessions')->where('id', $id)->where('account_id', $actor->accountId)->where('device_id', $actor->deviceId)->lockForUpdate()->first();
        D::require($lease !== null && $lease->purpose === 'export' && $lease->session_id === $actor->sessionId && $lease->root_fingerprint === $actor->rootFingerprint, 'NOT_FOUND');
        D::require($lease->state === 'active' && $lease->expires_at > now()->format('Y-m-d H:i:s'), 'SYNC_CURSOR_EXPIRED');
        $counter = DB::table('sync_counters')->where('id', 1)->first();
        D::require($counter !== null && $counter->generation === $lease->transport_generation, 'SYNC_CURSOR_EXPIRED');

        return [$actor, $lease];
    }

    private function result(Actor $actor, stdClass $lease): array
    {
        return ['version' => 1, 'scope' => ['service_id' => config('api.service_id'), 'account_id' => $actor->accountId, 'root_fingerprint' => $actor->rootFingerprint, 'group_id' => $lease->scope_group_id],
            'descriptor' => json_decode($lease->descriptor), 'catalog_count' => (string) $lease->catalog_count, 'catalog_digest' => $lease->catalog_digest,
            'lease_expires_at_ms' => (string) (strtotime($lease->expires_at.' UTC') * 1000), 'maximum_expires_at_ms' => (string) (strtotime($lease->maximum_expires_at.' UTC') * 1000),
            'served_bytes' => (string) $lease->served_bytes, 'selection' => json_decode($lease->export_selection)];
    }

    public function start(Request $r, stdClass $selection): array
    {
        return DB::transaction(function () use ($r, $selection) {
            $body = (object) ['version' => 1, 'operation_id' => $selection->operation_id, 'group_id' => count($selection->group_ids) === 1 ? $selection->group_ids[0] : null];
            $snapshot = $this->snapshots->start($r, $body, 'export', $selection);
            [$actor, $lease] = $this->current($r, $snapshot['descriptor']->snapshot_id);
            if ($lease->export_selection !== null) {
                return $this->result($actor, $lease);
            }
            $items = [];
            $neededFiles = [];
            foreach (DB::table('snapshot_items')->where('snapshot_id', $lease->id)->orderBy('item_index')->get() as $row) {
                $entry = json_decode($row->inventory_record);
                $item = $entry->item;
                if (! $selection->include_history && ! in_array($item->revision_id, array_map(fn ($h) => $h->revision_id, $entry->reference->heads), true)) {
                    continue;
                }
                if (! $selection->include_trash && $entry->reference->tombstoned) {
                    continue;
                }
                $items[] = $item;
                $revision = DB::table('object_revisions')->where('revision_id', $item->revision_id)->first();
                foreach (json_decode($revision->signed_envelope)->header->context->attachments as $file) {
                    $neededFiles[$file->file_version_id] = true;
                }
            }
            $files = DB::table('snapshot_file_pins as p')->join('file_versions as v', 'p.file_version_id', '=', 'v.id')->join('file_objects as f', 'v.file_id', '=', 'f.id')->where('p.snapshot_id', $lease->id)->orderBy('v.id')->get(['v.*', 'f.current_version_id']);
            foreach ($files as $file) {
                if (! $selection->include_history && ! isset($neededFiles[$file->id]) && $file->id !== $file->current_version_id) {
                    continue;
                }
                $items[] = (object) ['group_id' => $file->group_id, 'object_kind' => 'file-manifest', 'object_id' => $file->file_id, 'revision_id' => $file->id, 'envelope_digest' => $file->manifest_digest, 'payload_status' => 'retained'];
            }
            usort($items, fn ($a, $b) => [$a->group_id, $a->object_kind, $a->object_id, $a->revision_id] <=> [$b->group_id, $b->object_kind, $b->object_id, $b->revision_id]);
            D::require(count($items) <= 51000 && count(array_unique(array_map(fn ($x) => $x->revision_id, $items))) === count($items), 'RESOURCE_LIMIT');
            $pages = [];
            foreach (array_chunk($items, 500) as $index => $part) {
                $page = (object) ['contract' => 'p02-v1', 'protocol' => 'anynote', 'protocol_version' => 1, 'purpose' => 'snapshot-page', 'snapshot_id' => $lease->id, 'page_index' => (string) $index, 'items' => $part];
                D::require(strlen(P::canonical($page)) <= 1048576, 'RESOURCE_LIMIT');
                $pages[] = $page;
                DB::table('export_snapshot_pages')->insert(['snapshot_id' => $lease->id, 'page_index' => $index, 'page_record' => P::canonical($page)]);
            }
            foreach ($items as $index => $item) {
                DB::table('export_snapshot_items')->insert(['snapshot_id' => $lease->id, 'item_index' => $index, 'group_id' => $item->group_id, 'object_kind' => $item->object_kind, 'revision_id' => $item->revision_id, 'item_record' => P::canonical($item)]);
            }
            $hash = hash_init('sha256');
            hash_update($hash, "AnyNote/p02-v1/hash/snapshot-inventory\0".pack('N', count($pages)).pack('J', count($items)));
            foreach ($pages as $index => $page) {
                hash_update($hash, pack('N3', $index, count($page->items), strlen(P::canonical($page))).P::binary(P::digest('p02-v1', 'snapshot-page', $page)));
            }
            $descriptor = json_decode($lease->descriptor);
            $descriptor->page_count = (string) count($pages);
            $descriptor->item_count = (string) count($items);
            $descriptor->inventory_digest = P::b64(hash_final($hash, true));
            DB::table('snapshot_sessions')->where('id', $lease->id)->update(['descriptor' => P::canonical($descriptor), 'export_selection' => P::canonical($selection)]);
            $lease = DB::table('snapshot_sessions')->where('id', $lease->id)->first();

            return $this->result($actor, $lease);
        }, 3);
    }

    public function status(Request $r, string $id): array
    {
        return DB::transaction(function () use ($r, $id) {
            [$actor, $lease] = $this->current($r, $id);
            foreach (DB::table('snapshot_catalog')->where('snapshot_id', $id)->get() as $row) {
                $this->notes->group($actor, $row->group_id);
            }

            return $this->result($actor, $lease);
        }, 3);
    }

    private function progress(stdClass $lease, string $kind, string $reference, int $index, int $bytes): void
    {
        $inserted = DB::table('snapshot_progress')->insertOrIgnore(['snapshot_id' => $lease->id, 'kind' => $kind, 'reference_id' => $reference, 'part_index' => $index, 'bytes' => $bytes]);
        if ($inserted) {
            D::require($bytes <= 116000000000 - (int) $lease->served_bytes, 'RESOURCE_LIMIT');
            DB::table('snapshot_sessions')->where('id', $lease->id)->update(['served_bytes' => (int) $lease->served_bytes + $bytes]);
            $lease->served_bytes += $bytes;
        }
    }

    public function catalog(Request $r, string $id, int $start): array
    {
        return DB::transaction(function () use ($r, $id, $start) {
            [$actor, $lease] = $this->current($r, $id);
            D::require($start <= $lease->catalog_count, 'INVALID_REQUEST');
            $rows = DB::table('snapshot_catalog')->where('snapshot_id', $id)->where('item_index', '>=', $start)->orderBy('item_index')->limit(20)->get();
            $groups = [];
            foreach ($rows as $row) {
                $this->notes->group($actor, $row->group_id);
                $groups[] = json_decode($row->status_record);
            }

            return ['version' => 1, 'snapshot_id' => $id, 'start' => (string) $start, 'groups' => $groups, 'next' => $start + count($groups) < $lease->catalog_count ? (string) ($start + count($groups)) : null];
        }, 3);
    }

    public function page(Request $r, string $id, int $index): array
    {
        return DB::transaction(function () use ($r, $id, $index) {
            [$actor, $lease] = $this->current($r, $id);
            $row = DB::table('export_snapshot_pages')->where('snapshot_id', $id)->where('page_index', $index)->first();
            D::require($row !== null, 'NOT_FOUND');
            $page = json_decode($row->page_record);
            foreach ($page->items as $item) {
                $this->notes->group($actor, $item->group_id);
            }

            return ['version' => 1, 'scope' => ['service_id' => config('api.service_id'), 'account_id' => $actor->accountId, 'root_fingerprint' => $actor->rootFingerprint, 'group_id' => $lease->scope_group_id], 'page' => $page];
        }, 3);
    }

    public function headers(Request $r, string $id, int $start): array
    {
        return DB::transaction(function () use ($r, $id, $start) {
            [$actor, $lease] = $this->current($r, $id);
            $count = DB::table('export_snapshot_items')->where('snapshot_id', $id)->count();
            D::require($start <= $count, 'INVALID_REQUEST');
            $items = [];
            $bytes = 128;
            foreach (DB::table('export_snapshot_items')->where('snapshot_id', $id)->where('item_index', '>=', $start)->orderBy('item_index')->limit(100)->get() as $row) {
                $item = json_decode($row->item_record);
                $this->notes->group($actor, $row->group_id);
                if ($item->object_kind === 'file-manifest') {
                    $stored = DB::table('file_versions')->where('id', $row->revision_id)->first();
                    $record = json_decode($stored->manifest_record);
                    unset($record->version);
                    $record->record_kind = 'file-manifest';
                    $envelope = $record->envelope;
                    $length = strlen(P::canonical($record));
                } else {
                    $stored = DB::table('object_revisions')->where('revision_id', $row->revision_id)->first();
                    $envelope = json_decode($stored->signed_envelope);
                    if ($stored->payload_status === 'pruned') {
                        $length = strlen(P::canonical((object) ['payload_status' => 'pruned', 'record_kind' => $item->object_kind, 'envelope' => $envelope]));
                    } else {
                        $wrap = DB::table('object_key_wraps')->where('revision_id', $row->revision_id)->first();
                        $length = strlen(P::canonical((object) ['envelope' => $envelope, 'wrap' => json_decode($wrap->wrap_record), 'ciphertext' => ''])) + intdiv((int) $stored->ciphertext_bytes * 4 + 2, 3);
                    }
                }
                $entry = ['item' => $item, 'envelope' => $envelope, 'record_bytes' => (string) $length];
                $size = strlen(json_encode($entry, JSON_THROW_ON_ERROR));
                if ($items !== [] && $bytes + $size > 1048576) {
                    break;
                }
                D::require($size <= 1048448, 'RESOURCE_LIMIT');
                $items[] = $entry;
                $bytes += $size;
            }

            return ['version' => 1, 'snapshot_id' => $id, 'start' => (string) $start, 'items' => $items, 'next' => $start + count($items) < $count ? (string) ($start + count($items)) : null];
        }, 3);
    }

    public function record(Request $r, string $id, string $revision): array
    {
        return DB::transaction(function () use ($r, $id, $revision) {
            [$actor, $lease] = $this->current($r, $id);
            $row = DB::table('export_snapshot_items')->where('snapshot_id', $id)->where('revision_id', $revision)->first();
            D::require($row !== null, 'NOT_FOUND');
            $item = json_decode($row->item_record);
            $this->notes->group($actor, $item->group_id);
            if ($item->object_kind === 'file-manifest') {
                $record = $this->files->manifest(app(Sessions::class)->secret($r), $revision);
                $result = ['record_kind' => 'file-manifest', 'envelope' => $record->envelope, 'wrap' => $record->wrap, 'manifest_ciphertext' => $record->manifest_ciphertext];
            } else {
                $revisionRow = DB::table('object_revisions')->where('revision_id', $revision)->first();
                $wrap = DB::table('object_key_wraps')->where('revision_id', $revision)->first();
                $result = $item->payload_status === 'pruned' ? ['payload_status' => 'pruned', 'record_kind' => $item->object_kind, 'envelope' => json_decode($revisionRow->signed_envelope)] : ['envelope' => json_decode($revisionRow->signed_envelope), 'wrap' => json_decode($wrap->wrap_record), 'ciphertext' => P::b64($revisionRow->ciphertext)];
            }
            $this->progress($lease, 'record', $revision, 0, strlen(P::canonical((object) $result)));

            return ['version' => 1, 'snapshot_id' => $id, 'item' => $item, 'record' => $result];
        }, 3);
    }

    public function chunk(Request $r, string $id, string $version, int $index): array
    {
        return DB::transaction(function () use ($r, $id, $version, $index) {
            [$actor, $lease] = $this->current($r, $id);
            $item = DB::table('export_snapshot_items')->where('snapshot_id', $id)->where('object_kind', 'file-manifest')->where('revision_id', $version)->first();
            D::require($item !== null, 'NOT_FOUND');
            $this->notes->group($actor, $item->group_id);
            [$handle, $bytes] = $this->files->download(app(Sessions::class)->secret($r), $version, $index);
            try {
                $this->progress($lease, 'chunk', $version, $index, $bytes);
            } catch (\Throwable $error) {
                fclose($handle);
                throw $error;
            }

            return [$handle, $bytes];
        }, 3);
    }

    public function renew(Request $r, string $id): array
    {
        return DB::transaction(function () use ($r, $id) {
            [$actor, $lease] = $this->current($r, $id);
            foreach (DB::table('snapshot_catalog')->where('snapshot_id', $id)->get() as $row) {
                $this->notes->group($actor, $row->group_id);
            }
            D::require($lease->served_bytes > $lease->renewed_bytes, 'INVALID_REQUEST');
            $expires = min(strtotime($lease->maximum_expires_at.' UTC'), max(strtotime($lease->expires_at.' UTC'), time() + 1800));
            DB::table('snapshot_sessions')->where('id', $id)->update(['expires_at' => gmdate('Y-m-d H:i:s', $expires), 'renewed_bytes' => $lease->served_bytes]);

            return $this->result($actor, DB::table('snapshot_sessions')->where('id', $id)->first());
        }, 3);
    }

    public function cancel(Request $r, string $id): array
    {
        return $this->snapshots->cancel($r, $id, 'export');
    }
}
