<?php

namespace App\Content;

use App\Backend\Authorization;
use App\Crypto\PublicProtocol as P;
use App\Devices\Protocol as D;
use App\Notes\Repository;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use stdClass;

final class Thumbnails
{
    public function __construct(private Repository $notes, private Authorization $authorization) {}

    public function link(Request $r, string $source, stdClass $record): array
    {
        return DB::transaction(function () use ($r, $source, $record) {
            $actor = $this->notes->actor($r);
            DB::table('gc_coordination')->where('singleton', 1)->lockForUpdate()->first();
            $b = $record->body;
            D::require($b->source_version_id === $source && $source !== $b->derived_version_id, 'INVALID_REQUEST');
            $group = $this->notes->group($actor, $b->group_id, 'write');
            $rows = DB::table('file_versions')->whereIn('id', [$source, $b->derived_version_id])->orderBy('id')->lockForUpdate()->get()->keyBy('id');
            $original = $rows->get($source);
            $derived = $rows->get($b->derived_version_id);
            D::require($original !== null && $derived !== null && $original->group_id === $group->id && $derived->group_id === $group->id && $original->state === 'committed' && $derived->state === 'committed', 'NOT_FOUND');
            D::require($original->manifest_digest === $b->source_envelope_digest && $derived->manifest_digest === $b->derived_envelope_digest, 'INVALID_CHUNK');
            $header = json_decode($derived->manifest_record)->envelope->header;
            D::require((int) $header->framing->plaintext_bytes <= 262144 && $header->context->author->account_id === $actor->accountId && $header->context->author->device_id === $actor->deviceId && D::equal($header->context->policy, $b->policy), 'INVALID_REQUEST');
            $context = (object) ['service_id' => $b->service_id, 'group_id' => $b->group_id, 'author' => $b->author, 'policy' => $b->policy];
            $this->authorization->expected($actor, $group, $context);
            P::verify('p13-content', 'derived-thumbnail-link', $b, $record->signature, $actor->signingKey);
            $digest = P::b64(hash('sha256', "AnyNote/P13/thumbnail-link\0".P::canonical($record), true));
            $old = DB::table('derived_preview_links')->where('account_id', $actor->accountId)->where('device_id', $actor->deviceId)->where('operation_id', $b->operation_id)->first();
            D::require(! DB::table('derived_preview_links')->where('source_version_id', $b->derived_version_id)->exists() && ! DB::table('derived_preview_links')->where('derived_version_id', $source)->exists(), 'INVALID_REQUEST');
            if ($old) {
                D::require($old->request_digest === $digest, 'IDEMPOTENCY_MISMATCH');
            } else {
                D::require(! DB::table('derived_preview_links')->where('source_version_id', $source)->where('derived_version_id', $b->derived_version_id)->exists(), 'IDEMPOTENCY_MISMATCH');
                DB::table('derived_preview_links')->insert(['group_id' => $group->id, 'source_version_id' => $source, 'derived_version_id' => $b->derived_version_id, 'operation_id' => $b->operation_id, 'account_id' => $actor->accountId, 'device_id' => $actor->deviceId, 'request_digest' => $digest, 'signed_record' => P::canonical($record)]);
            }

            return ['version' => 1, 'group_id' => $group->id, 'source_version_id' => $source, 'derived_version_id' => $b->derived_version_id, 'operation_id' => $b->operation_id, 'digest' => $digest, 'state' => 'LINKED'];
        }, 3);
    }
}
