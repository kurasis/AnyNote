<?php

namespace App\Files;

use App\Backend\Actor;
use App\Backend\Authorization;
use App\Backend\QuotaLedger;
use App\Backend\SyncWriter;
use App\Crypto\PublicProtocol as P;
use App\Devices\Protocol as D;
use App\Notes\Repository;
use Illuminate\Support\Facades\DB;
use stdClass;

/** Actor -> GC -> group -> upload/file -> quota -> counter (LAST). */
final class Service
{
    public const CHUNK = 8388608;

    public const OVERHEAD = 65584;

    public function __construct(private Authorization $auth, private QuotaLedger $quota, private SyncWriter $sync, private P $protocol, private BlobStore $blobs) {}

    private function boundary(): void
    {
        D::require(DB::table('gc_coordination')->where('singleton', 1)->lockForUpdate()->first() !== null, 'TEMPORARY_UNAVAILABLE');
    }

    public function reserve(string $secret, string $group, stdClass $request): array
    {
        $c = $this->protocol->decode('p02-file-c1', 'context', P::canonical($request->context));
        D::require($c->group_id === $group && P::isBinary($request->upload_id, 16) && P::counter($request->plaintext_bytes, '1000000000'), 'INVALID_REQUEST');
        $size = (int) $request->plaintext_bytes;
        $reserved = $size + (int) ceil($size / self::CHUNK) * 16 + self::OVERHEAD;
        $digest = P::b64(hash('sha256', P::canonical($request), true));

        return DB::transaction(function () use ($secret, $c, $request, $size, $reserved, $digest) {
            $a = $this->auth->actor($secret);
            $this->boundary();
            $g = app(Repository::class)->group($a, $c->group_id);
            D::require($c->author->account_id === $a->accountId && $c->author->device_id === $a->deviceId, 'INVALID_SIGNATURE');
            $old = DB::table('upload_sessions')->where('id', $request->upload_id)->lockForUpdate()->first();
            if ($old) {
                D::require($old->account_id === $a->accountId && $old->device_id === $a->deviceId && $old->group_id === $g->id, 'NOT_FOUND');
                D::require($old->request_digest === $digest, 'IDEMPOTENCY_MISMATCH');

                return $this->statusValue($old);
            }
            app(Repository::class)->group($a, $g->id, 'write');
            $this->auth->expected($a, $g, $c);
            D::require(! DB::table('file_publication_ids')->where('account_id', $a->accountId)->where('device_id', $a->deviceId)->where('operation_id', $c->operation_id)->exists(), 'IDEMPOTENCY_MISMATCH');
            D::require(! DB::table('upload_sessions')->where('file_version_id', $c->file_version_id)->exists() && ! DB::table('mutation_receipts')->where('account_id', $a->accountId)->where('device_id', $a->deviceId)->where('operation_id', $c->operation_id)->exists() && ! DB::table('group_security_receipts')->where('account_id', $a->accountId)->where('device_id', $a->deviceId)->where('operation_id', $c->operation_id)->exists(), 'IDEMPOTENCY_MISMATCH');
            $file = DB::table('file_objects')->where('id', $c->file_id)->lockForUpdate()->first();
            if ($file) {
                D::require($file->group_id === $g->id && ! $file->tombstoned, 'NOT_FOUND');
                $parent = DB::table('file_versions')->where('id', $file->current_version_id)->first();
                D::require(count($c->parents) === 1 && $parent && $c->parents[0]->revision_id === $parent->id && $c->parents[0]->envelope_digest === $parent->manifest_digest, 'STALE_REVISION');
            } else {
                D::require($c->parents === [], 'STALE_REVISION');
                DB::table('file_objects')->insert(['id' => $c->file_id, 'group_id' => $g->id]);
            }
            $ledgers = $this->quota->lock($a->accountId, $g->id);
            $this->blobs->capacity($reserved + (int) $ledgers[0]->reserved_bytes);
            $this->quota->apply($ledgers, 0, $reserved);
            DB::table('quota_reservations')->insert(['id' => $request->upload_id, 'account_id' => $a->accountId, 'device_id' => $a->deviceId, 'group_id' => $g->id, 'bytes' => $reserved, 'state' => 'reserved', 'expires_at' => now()->addHours(72)]);
            DB::table('file_versions')->insert(['id' => $c->file_version_id, 'file_id' => $c->file_id, 'group_id' => $g->id, 'uploader_account_id' => $a->accountId, 'manifest_digest' => P::b64(str_repeat("\0", 32)), 'state' => 'staged', 'ciphertext_bytes' => 0]);
            DB::table('upload_sessions')->insert(['id' => $request->upload_id, 'account_id' => $a->accountId, 'device_id' => $a->deviceId, 'group_id' => $g->id, 'file_version_id' => $c->file_version_id, 'reservation_id' => $request->upload_id, 'state' => 'reserved', 'expires_at' => now()->addHours(72), 'created_at' => now(), 'progress_at' => now(), 'context_record' => P::canonical($c), 'plaintext_bytes' => $size, 'request_digest' => $digest]);
            DB::table('file_publication_ids')->insert(['account_id' => $a->accountId, 'device_id' => $a->deviceId, 'operation_id' => $c->operation_id, 'upload_id' => $request->upload_id]);

            return $this->statusValue(DB::table('upload_sessions')->where('id', $request->upload_id)->first());
        }, 3);
    }

    private function upload(string $secret, string $id, bool $write = false): array
    {
        $a = $this->auth->actor($secret);
        $hint = DB::table('upload_sessions')->where('id', $id)->first();
        D::require($hint && $hint->account_id === $a->accountId && $hint->device_id === $a->deviceId, 'NOT_FOUND');
        $this->boundary();
        $g = app(Repository::class)->group($a, $hint->group_id);
        $u = DB::table('upload_sessions')->where('id', $id)->lockForUpdate()->first();
        D::require($u && $u->account_id === $a->accountId && $u->device_id === $a->deviceId, 'NOT_FOUND');
        if ($write) {
            D::require(in_array($u->state, ['reserved', 'receiving'], true) && $u->expires_at > now()->format('Y-m-d H:i:s'), 'UPLOAD_EXPIRED');
            $context = json_decode($u->context_record);
            D::require($context->policy->key_epoch === (string) $g->epoch_number && $context->policy->epoch_digest === $g->epoch_digest, 'REKEY_RESTART_REQUIRED');
            app(Repository::class)->group($a, $g->id, 'write');
            $this->auth->expected($a, $g, $context);
        }

        return [$a, $g, $u];
    }

    private function statusValue(stdClass $u): array
    {
        $parts = DB::table('upload_parts')->where('upload_id', $u->id)->orderBy('chunk_index')->get()->map(fn ($p) => ['index' => (string) $p->chunk_index, 'ciphertext_bytes' => (string) $p->ciphertext_bytes, 'ciphertext_digest' => $p->digest])->all();
        $r = DB::table('quota_reservations')->where('id', $u->reservation_id)->first();

        return ['version' => 1, 'upload_id' => $u->id, 'group_id' => $u->group_id, 'file_version_id' => $u->file_version_id, 'state' => strtoupper($u->state), 'expires_at_ms' => (string) (strtotime($u->expires_at.' UTC') * 1000), 'reserved_bytes' => (string) $r->bytes, 'parts' => $parts, 'receipt' => $u->receipt_record ? json_decode($u->receipt_record, true) : null];
    }

    public function status(string $secret, string $id): array
    {
        return DB::transaction(function () use ($secret, $id) {
            [, , $u] = $this->upload($secret, $id);

            return $this->statusValue($u);
        }, 3);
    }

    public function part(string $secret, string $id, int $index, $input): array
    {
        // Authenticate and freeze public size before accepting any blob. Recheck after I/O.
        $length = DB::transaction(function () use ($secret, $id, $index) {
            [, , $u] = $this->upload($secret, $id, true);
            D::require($index >= 0 && $index < (int) ceil($u->plaintext_bytes / self::CHUNK), 'INVALID_REQUEST');

            return min(self::CHUNK, $u->plaintext_bytes - $index * self::CHUNK) + 16;
        }, 3);
        $blob = $this->blobs->stage($input, $length);
        $adopted = false;
        try {
            $result = DB::transaction(function () use ($secret, $id, $index, $blob, &$adopted) {
                [, , $u] = $this->upload($secret, $id, true);
                $old = DB::table('upload_parts')->where('upload_id', $id)->where('chunk_index', $index)->first();
                if ($old) {
                    D::require($old->digest === $blob['digest'] && (int) $old->ciphertext_bytes === $blob['ciphertext_bytes'], 'IDEMPOTENCY_MISMATCH');
                    $this->blobs->verify($old);
                } else {
                    DB::table('upload_parts')->insert(['id' => P::b64(random_bytes(16)), 'upload_id' => $id, 'chunk_index' => $index, ...$blob]);
                    $adopted = true;
                    // Only a new durable part renews inactivity, bounded to seven days overall.
                    $expires = min(now()->addHours(72)->format('Y-m-d H:i:s'), date('Y-m-d H:i:s', strtotime($u->created_at.' UTC') + 604800));
                    DB::table('upload_sessions')->where('id', $id)->update(['state' => 'receiving', 'progress_at' => now(), 'expires_at' => $expires]);
                    DB::table('quota_reservations')->where('id', $u->reservation_id)->update(['expires_at' => $expires]);
                }

                return ['index' => (string) $index, 'ciphertext_bytes' => (string) $blob['ciphertext_bytes'], 'ciphertext_digest' => $blob['digest']];
            }, 3);
        } catch (\Throwable $e) {
            // A lost DB commit result may have adopted it: references decide, not a flag.
            $adopted = DB::table('upload_parts')->where('blob_id', $blob['blob_id'])->exists();
            throw $e;
        } finally {
            if (! $adopted) {
                $this->blobs->remove($blob['blob_id']);
            }
        }

        return $result;
    }

    public function commit(string $secret, string $id, stdClass $record): array
    {
        return DB::transaction(function () use ($secret, $id, $record) {
            [$a, $g, $u] = $this->upload($secret, $id);
            $h = $this->protocol->decode('p02-file-c1', 'header', P::canonical($record->envelope->header));
            $w = $this->protocol->decode('p02-file-c1', 'wrap', P::canonical($record->wrap));
            P::verify('p02-file-c1', 'file-manifest', $h, $record->envelope->signature, $a->signingKey);
            D::require(P::canonical($h->context) === $u->context_record && P::canonical($w->context) === $u->context_record && $h->key_wrap_digest === P::digest('p02-file-c1', 'key-wrap', $w), 'INVALID_CHUNK');
            $encoded = P::canonical($record);
            $requestDigest = P::b64(hash('sha256', $encoded, true));
            $version = DB::table('file_versions')->where('id', $u->file_version_id)->lockForUpdate()->first();
            if ($u->state === 'committed') {
                $matches = $version->state === 'deleted'
                    ? hash_equals(json_decode($version->manifest_record)->request_digest, $requestDigest)
                    : $version->manifest_record === $encoded;
                D::require($matches, 'IDEMPOTENCY_MISMATCH');

                return json_decode($u->receipt_record, true);
            }
            $this->upload($secret, $id, true);
            $c = $h->context;
            $file = DB::table('file_objects')->where('id', $c->file_id)->lockForUpdate()->first();
            D::require($file->current_version_id === ($c->parents[0]->revision_id ?? null), 'STALE_REVISION');
            D::require($h->framing->plaintext_bytes === (string) $u->plaintext_bytes && $h->framing->chunk_plaintext_bytes === (string) self::CHUNK && (int) $h->framing->chunk_count === (int) ceil($u->plaintext_bytes / self::CHUNK) && count($h->framing->parts) === (int) $h->framing->chunk_count, 'INVALID_CHUNK');
            $manifest = P::binary($record->manifest_ciphertext);
            D::require(strlen($manifest) <= 65536 && strlen($manifest) >= 16 && strlen($manifest) === (int) $h->manifest_ciphertext_bytes && P::b64(hash('sha256', $manifest, true)) === $h->manifest_ciphertext_digest && strlen(P::binary($w->ciphertext)) === 48, 'INVALID_CHUNK');
            $parts = DB::table('upload_parts')->where('upload_id', $id)->orderBy('chunk_index')->get();
            D::require($parts->count() === count($h->framing->parts), 'INVALID_CHUNK');
            $actual = strlen($manifest) + 48;
            foreach ($parts as $index => $p) {
                $signed = $h->framing->parts[$index];
                D::require((int) $p->chunk_index === $index && $signed->index === (string) $index && $signed->ciphertext_digest === $p->digest && $signed->ciphertext_bytes === (string) $p->ciphertext_bytes && (int) $p->ciphertext_bytes === min(self::CHUNK, $u->plaintext_bytes - $index * self::CHUNK) + 16, 'INVALID_CHUNK');
                $this->blobs->verify($p);
                $actual += (int) $p->ciphertext_bytes;
                DB::table('file_chunks')->insert(['id' => P::b64(random_bytes(16)), 'file_version_id' => $version->id, 'chunk_index' => $index, 'blob_id' => $p->blob_id, 'digest' => $p->digest, 'ciphertext_bytes' => $p->ciphertext_bytes]);
            }
            $reservation = DB::table('quota_reservations')->where('id', $u->reservation_id)->lockForUpdate()->first();
            D::require($reservation->state === 'reserved' && $actual <= (int) $reservation->bytes, 'QUOTA_EXCEEDED');
            $this->quota->apply($this->quota->lock($a->accountId, $g->id), $actual, -(int) $reservation->bytes);
            $envelopeDigest = P::digest('p02-file-c1', 'file-envelope', $record->envelope);
            DB::table('file_versions')->where('id', $version->id)->update(['state' => 'committed', 'manifest_digest' => $envelopeDigest, 'manifest_record' => $encoded, 'ciphertext_bytes' => $actual, 'committed_at' => now(), 'unattached_expires_at' => now()->addDays(30)]);
            DB::table('file_objects')->where('id', $c->file_id)->update(['current_version_id' => $version->id]);
            DB::table('quota_reservations')->where('id', $u->reservation_id)->update(['state' => 'committed', 'committed_bytes' => $actual]);
            DB::table('publication_journal')->insert(['id' => P::b64(random_bytes(16)), 'account_id' => $a->accountId, 'device_id' => $a->deviceId, 'file_version_id' => $version->id, 'operation_id' => $c->operation_id, 'state' => 'unattached']);
            $cursor = $this->sync->append([['group_id' => $g->id, 'kind' => 'file', 'object_id' => $c->file_id, 'revision_id' => $version->id, 'digest' => $envelopeDigest]]);
            $result = ['version' => 1, 'upload_id' => $id, 'file_id' => $c->file_id, 'file_version_id' => $version->id, 'group_id' => $g->id, 'operation_id' => $c->operation_id, 'envelope_digest' => $envelopeDigest, 'ciphertext_bytes' => (string) $actual, 'state' => 'COMMITTED', 'cursor' => $cursor];
            DB::table('upload_sessions')->where('id', $id)->update(['state' => 'committed', 'receipt_record' => json_encode($result, JSON_THROW_ON_ERROR)]);
            // This family stays separately scoped; the upload ID and signed operation are durable.
            DB::table('mutation_receipts')->insert(['account_id' => $a->accountId, 'device_id' => $a->deviceId, 'operation_id' => $c->operation_id, 'family' => 'file', 'group_id' => $g->id, 'request_digest' => $requestDigest, 'result' => json_encode($result, JSON_THROW_ON_ERROR), 'expires_at' => now()->addDays(30)]);

            return $result;
        }, 3);
    }

    public function cancel(string $secret, string $id): array
    {
        return DB::transaction(function () use ($secret, $id) {
            [, , $u] = $this->upload($secret, $id);
            D::require($u->state !== 'committed', 'INVALID_REQUEST');
            $this->release($u, 'cancelled');

            return $this->statusValue(DB::table('upload_sessions')->where('id', $id)->first());
        }, 3);
    }

    private function release(stdClass $u, string $state): void
    {
        if (in_array($u->state, ['cancelled', 'expired'], true)) {
            return;
        }
        D::require(in_array($u->state, ['reserved', 'receiving'], true), 'INVALID_REQUEST');
        foreach (DB::table('upload_parts')->where('upload_id', $u->id)->get() as $part) {
            $this->blobs->remove($part->blob_id);
        }
        DB::table('upload_parts')->where('upload_id', $u->id)->delete();
        $r = DB::table('quota_reservations')->where('id', $u->reservation_id)->lockForUpdate()->first();
        D::require($r->state === 'reserved', 'INVALID_CHUNK');
        $this->quota->apply($this->quota->lock($u->account_id, $u->group_id), 0, -(int) $r->bytes);
        DB::table('quota_reservations')->where('id', $r->id)->update(['state' => 'released']);
        DB::table('upload_sessions')->where('id', $u->id)->update(['state' => $state]);
    }

    private function version(string $secret, string $id): array
    {
        $a = $this->auth->actor($secret);
        $this->boundary();
        $v = DB::table('file_versions')->where('id', $id)->first();
        D::require($v && $v->state === 'committed', 'NOT_FOUND');
        $g = app(Repository::class)->group($a, $v->group_id);

        return [$a, $g, $v];
    }

    public function manifest(string $secret, string $id): stdClass
    {
        return DB::transaction(function () use ($secret, $id) {
            [, , $v] = $this->version($secret, $id);

            return json_decode($v->manifest_record);
        }, 3);
    }

    /** Open under authorization/GC boundary; unlink cannot change this descriptor. */
    public function download(string $secret, string $id, int $index): array
    {
        return DB::transaction(function () use ($secret, $id, $index) {
            [, , $v] = $this->version($secret, $id);
            $this->boundary();
            $part = DB::table('file_chunks')->where('file_version_id', $v->id)->where('chunk_index', $index)->first();
            D::require($part !== null, 'NOT_FOUND');
            $this->blobs->verify($part);
            $handle = fopen($this->blobs->path($part->blob_id), 'rb');
            D::require($handle !== false, 'STORAGE_UNAVAILABLE');

            return [$handle, (int) $part->ciphertext_bytes];
        }, 3);
    }

    public function listing(string $secret, ?string $group, ?string $after): array
    {
        return DB::transaction(function () use ($secret, $group, $after) {
            $a = $this->auth->actor($secret);
            if ($group !== null) {
                app(Repository::class)->group($a, $group);
            }
            $q = DB::table('file_versions as v')->join('group_memberships as m', 'v.group_id', '=', 'm.group_id')->where('m.account_id', $a->accountId)->where('m.status', 'active')->where('v.state', 'committed');
            if ($group !== null) {
                $q->where('v.group_id', $group);
            } else {
                $q->where('v.uploader_account_id', $a->accountId)->whereNotExists(fn ($r) => $r->selectRaw('1')->from('attachment_refs as a')->whereColumn('a.file_version_id', 'v.id'));
            }
            if ($after !== null) {
                $q->where('v.id', '>', $after);
            }
            $rows = $q->orderBy('v.id')->limit(101)->get(['v.*']);
            $more = $rows->count() > 100;
            $items = [];
            foreach ($rows->take(100) as $v) {
                app(Repository::class)->group($a, $v->group_id);
                $items[] = ['file_id' => $v->file_id, 'file_version_id' => $v->id, 'group_id' => $v->group_id, 'envelope_digest' => $v->manifest_digest, 'ciphertext_bytes' => (string) $v->ciphertext_bytes, 'unattached_expires_at_ms' => (string) (strtotime($v->unattached_expires_at.' UTC') * 1000)];
            }

            return ['version' => 1, 'items' => $items, 'next_after' => $more ? end($items)['file_version_id'] : null];
        }, 3);
    }

    public function storage(string $secret): array
    {
        return DB::transaction(function () use ($secret) {
            $a = $this->auth->actor($secret);
            $global = DB::table('quota_ledgers')->where('scope', 'global')->first();

            return ['version' => 1, 'limit_bytes' => (string) $global->limit_bytes, 'committed_bytes' => (string) $global->committed_bytes, 'reserved_bytes' => (string) $global->reserved_bytes, 'pending_limit_bytes' => (string) $global->pending_limit_bytes, 'account_id' => $a->accountId, 'physical_overhead_included' => false];
        }, 3);
    }

    public function deleteUnattached(string $secret, string $id): array
    {
        return DB::transaction(function () use ($secret, $id) {
            [$a, $g, $v] = $this->version($secret, $id);
            app(Repository::class)->group($a, $g->id, 'write');
            D::require($v->uploader_account_id === $a->accountId || $g->owner_account_id === $a->accountId, 'ROLE_FORBIDDEN');
            $this->boundary();
            $v = DB::table('file_versions')->where('id', $id)->lockForUpdate()->first();
            D::require(! DB::table('attachment_refs')->where('file_version_id', $id)->exists() && ! DB::table('snapshot_file_pins')->where('file_version_id', $id)->exists(), 'INVALID_REQUEST');
            // Parent ancestry remains immutable. A successor pins its parent payload for P13.
            foreach (DB::table('file_versions')->where('file_id', $v->file_id)->where('state', 'committed')->get() as $other) {
                $context = json_decode($other->manifest_record)->envelope->header->context;
                foreach ($context->parents as $parent) {
                    D::require($parent->revision_id !== $id, 'INVALID_REQUEST');
                }
            }
            DB::table('file_versions')->where('id', $id)->update(['state' => 'reclaimable']);

            // Quota remains charged until physical deletion succeeds in the janitor.
            return ['version' => 1, 'file_version_id' => $id, 'state' => 'RECLAIMABLE'];
        }, 3);
    }

    /** Operator/local job, never a public arbitrary cleanup endpoint. */
    public function collect(int $limit = 50): array
    {
        D::require($limit >= 1 && $limit <= 100, 'INVALID_REQUEST');
        foreach (DB::table('snapshot_sessions')->where('state', 'active')->where('expires_at', '<=', now())->orderBy('id')->limit($limit)->get() as $hint) {
            DB::transaction(function () use ($hint) {
                DB::table('users')->where('id', $hint->account_id)->lockForUpdate()->first();
                $this->boundary();
                $lease = DB::table('snapshot_sessions')->where('id', $hint->id)->lockForUpdate()->first();
                if ($lease->state !== 'active' || $lease->expires_at > now()->format('Y-m-d H:i:s')) {
                    return;
                }
                foreach (['snapshot_file_pins', 'reference_pins', 'snapshot_items', 'snapshot_pages', 'snapshot_catalog'] as $table) {
                    DB::table($table)->where('snapshot_id', $lease->id)->delete();
                }
                DB::table('snapshot_sessions')->where('id', $lease->id)->update(['state' => 'expired']);
            }, 3);
        }
        $expired = 0;
        foreach (DB::table('upload_sessions')->whereIn('state', ['reserved', 'receiving'])->where('expires_at', '<=', now())->orderBy('id')->limit($limit)->get() as $hint) {
            $expired += DB::transaction(function () use ($hint) {
                // Account precedes group/GC, matching publication and security operations.
                DB::table('users')->where('id', $hint->account_id)->lockForUpdate()->first();
                $this->boundary();
                DB::table('groups')->where('id', $hint->group_id)->lockForUpdate()->first();
                $u = DB::table('upload_sessions')->where('id', $hint->id)->lockForUpdate()->first();
                if (! in_array($u->state, ['reserved', 'receiving'], true) || $u->expires_at > now()->format('Y-m-d H:i:s')) {
                    return 0;
                }
                $this->release($u, 'expired');

                return 1;
            }, 3);
        }
        foreach (DB::table('file_versions')->where('state', 'committed')->where('unattached_expires_at', '<=', now())->orderBy('id')->limit($limit)->get() as $hint) {
            DB::transaction(function () use ($hint) {
                DB::table('users')->where('id', $hint->uploader_account_id)->lockForUpdate()->first();
                $this->boundary();
                DB::table('groups')->where('id', $hint->group_id)->lockForUpdate()->first();
                $file = DB::table('file_versions')->where('id', $hint->id)->lockForUpdate()->first();
                if ($file->state !== 'committed' || $file->unattached_expires_at > now()->format('Y-m-d H:i:s') || ! $this->unreferenced($file)) {
                    return;
                }
                DB::table('file_versions')->where('id', $file->id)->update(['state' => 'reclaimable']);
            }, 3);
        }
        $deleted = 0;
        foreach (DB::table('file_versions')->where('state', 'reclaimable')->orderBy('id')->limit($limit)->get() as $hint) {
            $deleted += DB::transaction(function () use ($hint) {
                DB::table('users')->where('id', $hint->uploader_account_id)->lockForUpdate()->first();
                $this->boundary();
                DB::table('groups')->where('id', $hint->group_id)->lockForUpdate()->first();
                $v = DB::table('file_versions')->where('id', $hint->id)->lockForUpdate()->first();
                if ($v->state !== 'reclaimable' || ! $this->unreferenced($v)) {
                    return 0;
                }
                foreach (DB::table('file_chunks')->where('file_version_id', $v->id)->get() as $part) {
                    $this->blobs->remove($part->blob_id);
                }
                DB::table('file_chunks')->where('file_version_id', $v->id)->delete();
                // Upload rows are retained as receipts but no longer retain physical chunks.
                $upload = DB::table('upload_sessions')->where('file_version_id', $v->id)->first();
                DB::table('upload_parts')->where('upload_id', $upload->id)->delete();
                $this->quota->apply($this->quota->lock($v->uploader_account_id, $v->group_id), -(int) $v->ciphertext_bytes, 0);
                $old = json_decode($v->manifest_record);
                $compact = P::canonical((object) ['envelope' => $old->envelope, 'request_digest' => P::b64(hash('sha256', $v->manifest_record, true))]);
                DB::table('file_versions')->where('id', $v->id)->update(['state' => 'deleted', 'manifest_record' => $compact]);
                DB::table('publication_journal')->where('file_version_id', $v->id)->update(['state' => 'cancelled']);
                DB::table('file_objects')->where('id', $v->file_id)->where('current_version_id', $v->id)->update(['tombstoned' => true]);
                $this->sync->append([['group_id' => $v->group_id, 'kind' => 'file-delete', 'object_id' => $v->file_id, 'revision_id' => null, 'digest' => $v->manifest_digest]]);

                return 1;
            }, 3);
        }

        $orphans = DB::transaction(function () {
            $this->boundary();

            return $this->blobs->orphans();
        }, 3);

        return ['expired_uploads' => $expired, 'deleted_files' => $deleted, 'orphan_blobs' => $orphans];
    }

    private function unreferenced(stdClass $file): bool
    {
        if (DB::table('attachment_refs')->where('file_version_id', $file->id)->exists() || DB::table('snapshot_file_pins')->where('file_version_id', $file->id)->exists()) {
            return false;
        }
        foreach (DB::table('file_versions')->where('file_id', $file->file_id)->whereNotNull('manifest_record')->whereIn('state', ['committed', 'reclaimable'])->get() as $successor) {
            foreach (json_decode($successor->manifest_record)->envelope->header->context->parents as $parent) {
                if ($parent->revision_id === $file->id) {
                    return false;
                }
            }
        }
        foreach (DB::table('upload_sessions')->where('group_id', $file->group_id)->whereIn('state', ['reserved', 'receiving'])->get() as $upload) {
            foreach (json_decode($upload->context_record)->parents as $parent) {
                if ($parent->revision_id === $file->id) {
                    return false;
                }
            }
        }

        return true;
    }
}
