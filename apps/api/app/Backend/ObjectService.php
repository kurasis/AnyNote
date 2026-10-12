<?php

namespace App\Backend;

use App\Crypto\PublicProtocol as P;
use App\Http\ApiException;
use Illuminate\Support\Facades\DB;

final class ObjectService
{
    public function __construct(private P $protocol, private Authorization $authorization, private QuotaLedger $quota, private SyncWriter $sync) {}

    /** Internal typed service; P09 owns HTTP publication and client conflict flows. */
    public function commit(string $sessionSecret, string $requestBytes): array
    {
        $request = $this->protocol->decode('p04-api', 'object-commit', $requestBytes);

        return DB::transaction(function () use ($sessionSecret, $request) {
            $a = $this->authorization->actor($sessionSecret);
            $g = $this->authorization->group($a, $request->group_id);
            $b = $this->protocol->bundle(P::canonical($request->bundle), $a->signingKey);
            $c = $b->envelope->header->context;
            if ($c->object_id !== $request->object_id || $c->object_kind !== $request->object_kind || $c->action !== $request->action || $c->thread_id !== $request->thread_id) {
                throw new ApiException('MALFORMED_ENVELOPE');
            }
            if ($c->group_id !== $g->id || $c->service_id !== config('api.service_id') || $c->author->account_id !== $a->accountId || $c->author->device_id !== $a->deviceId || $c->author->root_fingerprint !== $a->rootFingerprint || $c->author->recovery_generation !== $a->generation) {
                throw new ApiException('INVALID_SIGNATURE');
            }
            $digest = P::digest('p02-v1', 'bundle', $b);
            $receiptQuery = DB::table('mutation_receipts')->where('account_id', $a->accountId)->where('device_id', $a->deviceId)->where('operation_id', $c->operation_id);
            if ($old = $receiptQuery->first()) {
                if ($old->request_digest !== $digest || $old->family !== 'object') {
                    throw new ApiException('IDEMPOTENCY_MISMATCH');
                }

                // Reauthorize current access, but a committed exact retry survives head changes.
                return json_decode($old->result, true, 32, JSON_THROW_ON_ERROR);
            }
            $this->authorization->group($a, $g->id, 'write');
            $this->authorization->expected($a, $g, $c);
            if ($c->object_kind === 'group-metadata' && $c->object_id !== $g->id) {
                throw new ApiException('MALFORMED_ENVELOPE');
            }
            if ($c->thread_id !== null) {
                $thread = DB::table('objects')->where('group_id', $g->id)->where('id', $c->thread_id)->lockForUpdate()->first();
                if (! $thread || $thread->kind !== 'thread' || $thread->tombstoned) {
                    throw new ApiException('NOT_FOUND');
                }
                if ($thread->archived) {
                    throw new ApiException('ROLE_FORBIDDEN');
                }
            }
            $object = DB::table('objects')->where('group_id', $g->id)->where('id', $c->object_id)->lockForUpdate()->first();
            if ($object && ($object->group_id !== $g->id || $object->kind !== $c->object_kind || $object->thread_id !== $c->thread_id)) {
                throw new ApiException('NOT_FOUND');
            }
            if (! $object && ($c->action !== 'create' || DB::table('objects')->where('id', $c->object_id)->exists())) {
                throw new ApiException('NOT_FOUND');
            }
            if (($c->action === 'create') !== ($object === null)) {
                throw new ApiException('STALE_REVISION');
            }
            if ($object && (($c->action === 'restore') !== (bool) $object->tombstoned)) {
                throw new ApiException('STALE_REVISION');
            }
            // Archive is a signed metadata state; group archive requires owner policy P10.
            if (($c->object_kind === 'entry' && $c->archived) || ($c->object_kind === 'group-metadata' && $c->archived !== ($g->state === 'archived'))) {
                throw new ApiException('MALFORMED_ENVELOPE');
            }
            $heads = DB::table('object_heads')->where('object_id', $c->object_id)->orderBy('revision_id')->pluck('revision_id')->all();
            if ($heads !== array_map(fn ($p) => $p->revision_id, $c->parents)) {
                throw new ApiException('STALE_REVISION');
            }
            foreach ($c->parents as $parent) {
                $row = DB::table('object_revisions')->where('group_id', $g->id)->where('object_id', $c->object_id)->where('revision_id', $parent->revision_id)->first();
                if (! $row || $row->envelope_digest !== $parent->envelope_digest) {
                    throw new ApiException('STALE_REVISION');
                }
            }
            if (DB::table('object_revisions')->where('revision_id', $c->revision_id)->exists() || DB::table('object_revisions')->where('author_account_id', $a->accountId)->where('author_device_id', $a->deviceId)->where('operation_id', $c->operation_id)->exists()) {
                throw new ApiException('REVISION_ID_CONFLICT');
            }
            $files = [];
            foreach ($c->attachments as $attachment) {
                $file = DB::table('file_versions')->where('id', $attachment->file_version_id)->where('group_id', $g->id)->where('file_id', $attachment->file_id)->lockForUpdate()->first();
                if (! $file || $file->state !== 'committed' || $file->manifest_digest !== $attachment->envelope_digest) {
                    throw new ApiException('NOT_FOUND');
                }
                $files[] = $file;
            }
            $ledgers = $this->quota->lock($a->accountId, $g->id);
            $ciphertext = P::binary($b->ciphertext);
            $bytes = strlen($ciphertext) + strlen(P::binary($b->wrap->ciphertext));
            $this->quota->apply($ledgers, $bytes, 0);
            if (! $object) {
                DB::table('objects')->insert(['id' => $c->object_id, 'group_id' => $g->id, 'kind' => $c->object_kind, 'thread_id' => $c->thread_id]);
            }
            $envelopeDigest = P::digest('p02-v1', 'envelope', $b->envelope);
            DB::table('object_revisions')->insert(['revision_id' => $c->revision_id, 'object_id' => $c->object_id, 'group_id' => $g->id, 'author_account_id' => $a->accountId, 'author_device_id' => $a->deviceId, 'operation_id' => $c->operation_id, 'epoch_number' => (int) $c->policy->key_epoch, 'payload_schema' => $c->payload_schema, 'envelope_digest' => $envelopeDigest, 'signed_envelope' => P::canonical($b->envelope), 'ciphertext' => $ciphertext, 'ciphertext_bytes' => strlen($ciphertext)]);
            DB::table('object_key_wraps')->insert(['revision_id' => $c->revision_id, 'wrap_record' => P::canonical($b->wrap), 'ciphertext_bytes' => 48]);
            foreach ($c->parents as $parent) {
                DB::table('revision_parents')->insert(['group_id' => $g->id, 'object_id' => $c->object_id, 'revision_id' => $c->revision_id, 'parent_revision_id' => $parent->revision_id]);
            }
            DB::table('object_heads')->where('object_id', $c->object_id)->delete();
            DB::table('object_heads')->insert(['group_id' => $g->id, 'object_id' => $c->object_id, 'revision_id' => $c->revision_id]);
            DB::table('objects')->where('id', $c->object_id)->update(['archived' => $c->archived, 'tombstoned' => $c->action === 'soft-delete']);
            foreach ($files as $file) {
                DB::table('attachment_refs')->insert(['revision_id' => $c->revision_id, 'file_version_id' => $file->id, 'group_id' => $g->id]);
            }
            $cursor = $this->sync->append([['group_id' => $g->id, 'kind' => $c->object_kind, 'object_id' => $c->object_id, 'revision_id' => $c->revision_id, 'digest' => $envelopeDigest]]);
            DB::table('objects')->where('id', $c->object_id)->update(['updated_sequence' => $cursor['sequence'], ...($object === null ? ['created_sequence' => $cursor['sequence']] : [])]);
            $result = ['receipt' => ['contract' => 'p02-v1', 'protocol' => 'anynote', 'protocol_version' => 1, 'purpose' => 'mutation-receipt', 'operation_id' => $c->operation_id, 'revision_id' => $c->revision_id, 'envelope_digest' => $envelopeDigest, 'status' => 'COMMITTED', 'cursor' => $cursor], 'heads' => [['revision_id' => $c->revision_id, 'envelope_digest' => $envelopeDigest]]];
            $receiptQuery->insert(['account_id' => $a->accountId, 'device_id' => $a->deviceId, 'operation_id' => $c->operation_id, 'family' => 'object', 'group_id' => $g->id, 'request_digest' => $digest, 'result' => json_encode($result, JSON_THROW_ON_ERROR), 'expires_at' => now()->addDays(30)]);

            return $result;
        }, 3);
    }
}
